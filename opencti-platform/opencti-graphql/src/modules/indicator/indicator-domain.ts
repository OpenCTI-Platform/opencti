import * as R from 'ramda';
import moment from 'moment/moment';
import { batchListThroughGetTo, createEntity, createRelation, distributionEntities, patchAttribute, storeLoadByIdWithRefs, timeSeriesEntities } from '../../database/middleware';
import { listAllEntities, listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
import { BUS_TOPICS, logApp } from '../../config/conf';
import { notify } from '../../database/redis';
import { checkIndicatorSyntax } from '../../python/pythonBridge';
import { DatabaseError, FunctionalError } from '../../config/errors';
import { isStixCyberObservable } from '../../schema/stixCyberObservable';
import { RELATION_BASED_ON, RELATION_INDICATES } from '../../schema/stixCoreRelationship';
import {
  ABSTRACT_STIX_CYBER_OBSERVABLE,
  ABSTRACT_STIX_DOMAIN_OBJECT,
  buildRefRelationKey,
  INPUT_CREATED_BY,
  INPUT_EXTERNAL_REFS,
  INPUT_LABELS,
  INPUT_MARKINGS
} from '../../schema/general';
import { elCount } from '../../database/engine';
import { isEmptyField, READ_INDEX_STIX_DOMAIN_OBJECTS } from '../../database/utils';
import { cleanupIndicatorPattern, extractObservablesFromIndicatorPattern } from '../../utils/syntax';
import { computeValidPeriod } from './indicator-utils';
import { addFilter } from '../../utils/filtering/filtering-utils';
import type { AuthContext, AuthUser } from '../../types/user';
import { type BasicStoreEntityIndicator, ENTITY_TYPE_INDICATOR, type StoreEntityIndicator } from './indicator-types';
import type { IndicatorAddInput, QueryIndicatorsArgs, QueryIndicatorsNumberArgs } from '../../generated/graphql';
import type { NumberResult } from '../../types/store';
import {
  BUILT_IN_DECAY_RULES,
  computeLivePoints,
  computeLiveScore,
  computeNextScoreReactionDate,
  type DecayHistory,
  type DecayLiveDetails,
  type DecayRule,
  findDecayRuleForIndicator
} from './decay-domain';
import { isModuleActivated } from '../../domain/settings';
import { prepareDate } from '../../utils/format';
import { FilterMode, FilterOperator, OrderingMode } from '../../generated/graphql';

export const findById = (context: AuthContext, user: AuthUser, indicatorId: string) => {
  return storeLoadById<BasicStoreEntityIndicator>(context, user, indicatorId, ENTITY_TYPE_INDICATOR);
};

export const findAll = (context: AuthContext, user: AuthUser, args: QueryIndicatorsArgs) => {
  return listEntitiesPaginated<BasicStoreEntityIndicator>(context, user, [ENTITY_TYPE_INDICATOR], args);
};

/**
 * Compute live decay detail for an indicator.
 * @param context
 * @param user
 * @param indicator
 */
export const getDecayDetails = async (context: AuthContext, user: AuthUser, indicator: BasicStoreEntityIndicator) => {
  if (!indicator.x_opencti_decay_rule) {
    return null;
  }
  const details: DecayLiveDetails = {
    live_score: computeLiveScore(indicator),
    live_points: computeLivePoints(indicator),
  };
  return details;
};

export const findIndicatorsForDecay = (context: AuthContext, user: AuthUser, maxSize: number) => {
  const filters = {
    orderBy: 'next_score_reaction_date',
    orderMode: OrderingMode.Asc,
    mode: FilterMode.And,
    filters: [
      { key: ['next_score_reaction_date'], values: [prepareDate()], operator: FilterOperator.Lt },
      { key: ['revoked'], values: ['false'] },
    ],
    filterGroups: [],
  };
  const args = {
    filters,
    maxSize,
  };
  return listAllEntities<BasicStoreEntityIndicator>(context, user, [ENTITY_TYPE_INDICATOR], args);
};

export const createObservablesFromIndicator = async (
  context: AuthContext,
  user: AuthUser,
  input: { objectLabel?: string[] | null; objectMarking?: string[] | null; createdBy?: string | null; externalReferences?: string[] | null; },
  indicator: StoreEntityIndicator,
) => {
  const { pattern } = indicator;
  const observables = extractObservablesFromIndicatorPattern(pattern);
  const observablesToLink = [];
  for (let index = 0; index < observables.length; index += 1) {
    const observable = observables[index];
    const observableInput = {
      ...R.dissoc('type', observable),
      x_opencti_description: indicator.description
        ? indicator.description
        : `Simple observable of indicator {${indicator.name || indicator.pattern}}`,
      x_opencti_score: indicator.x_opencti_score,
      createdBy: input.createdBy,
      objectMarking: input.objectMarking,
      objectLabel: input.objectLabel,
      externalReferences: input.externalReferences,
      update: true,
    };
    try {
      const createdObservable = await createEntity(context, user, observableInput, observable.type);
      observablesToLink.push(createdObservable.id);
    } catch (err) {
      logApp.error(err, { input: observableInput });
    }
  }
  await Promise.all(
    observablesToLink.map((observableToLink) => {
      const relationInput = { fromId: indicator.id, toId: observableToLink, relationship_type: RELATION_BASED_ON };
      return createRelation(context, user, relationInput);
    })
  );
};

export const promoteIndicatorToObservable = async (context: AuthContext, user: AuthUser, indicatorId: string) => {
  const indicator: StoreEntityIndicator = await storeLoadByIdWithRefs(context, user, indicatorId) as StoreEntityIndicator;
  const objectLabel = (indicator[INPUT_LABELS] ?? []).map((n) => n.internal_id);
  const objectMarking = (indicator[INPUT_MARKINGS] ?? []).map((n) => n.internal_id);
  const externalReferences = (indicator[INPUT_EXTERNAL_REFS] ?? []).map((n) => n.internal_id);
  const createdBy = indicator[INPUT_CREATED_BY]?.internal_id;
  const input = { objectLabel, objectMarking, createdBy, externalReferences };
  return createObservablesFromIndicator(context, user, input, indicator);
};

export const addIndicator = async (context: AuthContext, user: AuthUser, indicator: IndicatorAddInput) => {
  let observableType: string = isEmptyField(indicator.x_opencti_main_observable_type) ? 'Unknown' : indicator.x_opencti_main_observable_type as string;
  if (observableType === 'File') {
    observableType = 'StixFile';
  }
  const isKnownObservable = observableType !== 'Unknown';
  if (isKnownObservable && !isStixCyberObservable(observableType)) {
    throw FunctionalError(`Observable type ${observableType} is not supported.`);
  }
  // check indicator syntax
  const patternType = indicator.pattern_type.toLowerCase();
  const formattedPattern = cleanupIndicatorPattern(patternType, indicator.pattern);
  const check = await checkIndicatorSyntax(context, user, patternType, formattedPattern);
  if (check === false) {
    throw FunctionalError(`Indicator of type ${indicator.pattern_type} is not correctly formatted.`);
  }
  const indicatorBaseScore = indicator.x_opencti_score ?? 50;
  const isDecayActivated = await isModuleActivated('INDICATOR_DECAY_MANAGER');
  // find default decay rule (even if decay is not activated, it is used to compute default validFrom and validUntil)
  const decayRule = findDecayRuleForIndicator(observableType, BUILT_IN_DECAY_RULES);
  const { validFrom, validUntil, revoked, validPeriod } = await computeValidPeriod(indicator, decayRule);
  const indicatorToCreate = R.pipe(
    R.dissoc('createObservables'),
    R.dissoc('basedOn'),
    R.assoc('pattern', formattedPattern),
    R.assoc('x_opencti_main_observable_type', observableType),
    R.assoc('x_opencti_score', indicatorBaseScore),
    R.assoc('x_opencti_detection', indicator.x_opencti_detection ?? false),
    R.assoc('valid_from', validFrom.toISOString()),
    R.assoc('valid_until', validUntil.toISOString()),
    R.assoc('revoked', revoked),
  )(indicator);
  let finalIndicatorToCreate;
  if (isDecayActivated) {
    const indicatorDecayRule = {
      decay_lifetime: decayRule.decay_lifetime,
      decay_pound: decayRule.decay_pound,
      decay_points: [...decayRule.decay_points],
      decay_revoke_score: decayRule.decay_revoke_score,
    };
    const nextScoreReactionDate = computeNextScoreReactionDate(indicatorBaseScore, indicatorBaseScore, decayRule, validFrom);
    const decayHistory: DecayHistory[] = [];
    decayHistory.push({
      updated_at: validFrom.toDate(),
      score: indicatorBaseScore,
    });
    finalIndicatorToCreate = {
      ...indicatorToCreate,
      next_score_reaction_date: nextScoreReactionDate,
      x_opencti_base_score: indicatorBaseScore,
      x_opencti_base_score_date: validFrom.toISOString(),
      x_opencti_decay_rule: indicatorDecayRule,
      x_opencti_decay_history: decayHistory,
    };
  } else {
    finalIndicatorToCreate = { ...indicatorToCreate };
  }
  // create the linked observables
  let observablesToLink: string[] = [];
  if (indicator.basedOn) {
    observablesToLink = indicator.basedOn;
  }
  if (!validPeriod) {
    throw DatabaseError('You cant create an indicator with valid_until less than valid_from', {
      input: finalIndicatorToCreate,
    });
  }
  const created = await createEntity(context, user, finalIndicatorToCreate, ENTITY_TYPE_INDICATOR);
  await Promise.all(
    observablesToLink.map((observableToLink) => {
      const input = { fromId: created.id, toId: observableToLink, relationship_type: RELATION_BASED_ON };
      return createRelation(context, user, input);
    })
  );
  if (observablesToLink.length === 0 && indicator.createObservables) {
    await createObservablesFromIndicator(context, user, indicator, created);
  }
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

export interface IndicatorPatch {
  revoked?: boolean,
  x_opencti_score?: number,
  x_opencti_decay_history?: DecayHistory[],
  next_score_reaction_date?: Date,
}

export const computeIndicatorDecayPatch = (indicator: BasicStoreEntityIndicator) => {
  // update x_opencti_score
  let patch: IndicatorPatch = {};
  const model = indicator.x_opencti_decay_rule;
  if (!model || !model.decay_points) {
    return null;
  }
  const newStableScore = model.decay_points.find((p) => (p || indicator.x_opencti_score) < indicator.x_opencti_score) || model.decay_revoke_score;
  if (newStableScore) {
    const decayHistory: DecayHistory[] = [...(indicator.x_opencti_decay_history ?? [])];
    decayHistory.push({
      updated_at: new Date(),
      score: newStableScore,
    });
    patch = {
      x_opencti_score: newStableScore,
      x_opencti_decay_history: decayHistory,
    };
    if (newStableScore <= model.decay_revoke_score) {
      // revoke
      patch = { ...patch, revoked: true };
    } else {
      // compute next_score_reaction_date
      const nextScoreReactionDate = computeNextScoreReactionDate(indicator.x_opencti_base_score, newStableScore, model as DecayRule, moment(indicator.valid_from));
      if (nextScoreReactionDate) {
        patch = { ...patch, next_score_reaction_date: nextScoreReactionDate };
      }
    }
  }
  return patch;
};

/**
 * Triggered by the decay manager when next_score_reaction_date is reached.
 * Compute the next step for Indicator as patch to applied to the database:
 * - change the current stable score to next
 * - update the next_score_reaction_date to next one
 * - revoke if the revoke score is reached
 * @param context
 * @param user
 * @param indicator
 */
export const updateIndicatorDecayScore = async (context: AuthContext, user: AuthUser, indicator: BasicStoreEntityIndicator) => {
  // update x_opencti_score
  const patch = computeIndicatorDecayPatch(indicator);
  if (!patch) {
    return null;
  }
  return patchAttribute(context, user, indicator.id, ENTITY_TYPE_INDICATOR, patch);
};

// region series
export const indicatorsTimeSeries = (context: AuthContext, user: AuthUser, args: any) => {
  return timeSeriesEntities(context, user, [ENTITY_TYPE_INDICATOR], args);
};

export const indicatorsTimeSeriesByEntity = (context: AuthContext, user: AuthUser, args: any) => {
  const { objectId } = args;
  const filters = addFilter(args.filters, buildRefRelationKey(RELATION_INDICATES, '*'), objectId);
  return timeSeriesEntities(context, user, [ENTITY_TYPE_INDICATOR], { ...args, filters });
};

export const indicatorsNumber = async (context: AuthContext, user: AuthUser, args: QueryIndicatorsNumberArgs): Promise<NumberResult> => {
  const countPromise = elCount(context, user, READ_INDEX_STIX_DOMAIN_OBJECTS, {
    ...args,
    types: [ENTITY_TYPE_INDICATOR]
  }) as Promise<number>;
  const totalPromise = elCount(
    context,
    user,
    READ_INDEX_STIX_DOMAIN_OBJECTS,
    { ...R.dissoc('endDate', args), types: [ENTITY_TYPE_INDICATOR] }
  ) as Promise<number>;
  const [count, total] = await Promise.all([countPromise, totalPromise]);
  return { count, total };
};

export const indicatorsNumberByEntity = async (context: AuthContext, user: AuthUser, args: QueryIndicatorsNumberArgs): Promise<NumberResult> => {
  const { objectId } = args;
  const filters = addFilter(null, buildRefRelationKey(RELATION_INDICATES, '*'), objectId);
  const countPromise = elCount(
    context,
    user,
    READ_INDEX_STIX_DOMAIN_OBJECTS,
    { ...args, types: [ENTITY_TYPE_INDICATOR], filters }
  );
  const totalPromise = elCount(
    context,
    user,
    READ_INDEX_STIX_DOMAIN_OBJECTS,
    { ...R.dissoc('endDate', args), types: [ENTITY_TYPE_INDICATOR], filters }
  );
  const [count, total] = await Promise.all([countPromise, totalPromise]);
  return { count, total };
};

export const indicatorsDistributionByEntity = async (context: AuthContext, user: AuthUser, args: any) => {
  const { objectId } = args;
  const filters = addFilter(args.filters, buildRefRelationKey(RELATION_INDICATES, '*'), objectId);
  return distributionEntities(context, user, [ENTITY_TYPE_INDICATOR], { ...args, filters });
};
// endregion

export const batchObservables = (context: AuthContext, user: AuthUser, indicatorIds: string[]) => {
  return batchListThroughGetTo(context, user, indicatorIds, RELATION_BASED_ON, ABSTRACT_STIX_CYBER_OBSERVABLE);
};
