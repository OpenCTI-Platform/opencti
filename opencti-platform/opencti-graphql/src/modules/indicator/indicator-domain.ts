import * as R from 'ramda';
import moment from 'moment/moment';
import { createEntity, createRelation, distributionEntities, patchAttribute, storeLoadByIdWithRefs, timeSeriesEntities } from '../../database/middleware';
import { type EntityOptions, listAllEntities, listEntitiesPaginated, listEntitiesThroughRelationsPaginated, storeLoadById } from '../../database/middleware-loader';
import { BUS_TOPICS, extendedErrors, logApp } from '../../config/conf';
import { notify } from '../../database/redis';
import { checkIndicatorSyntax } from '../../python/pythonBridge';
import { DatabaseError, FunctionalError, ValidationError } from '../../config/errors';
import { isStixCyberObservable } from '../../schema/stixCyberObservable';
import { RELATION_BASED_ON, RELATION_INDICATES } from '../../schema/stixCoreRelationship';
import {
  ABSTRACT_STIX_CYBER_OBSERVABLE,
  ABSTRACT_STIX_DOMAIN_OBJECT,
  buildRefRelationKey,
  INPUT_CREATED_BY,
  INPUT_EXTERNAL_REFS,
  INPUT_GRANTED_REFS,
  INPUT_LABELS,
  INPUT_MARKINGS
} from '../../schema/general';
import { elCount } from '../../database/engine';
import { isEmptyField, READ_INDEX_STIX_DOMAIN_OBJECTS } from '../../database/utils';
import { cleanupIndicatorPattern, extractObservablesFromIndicatorPattern, extractValidObservablesFromIndicatorPattern } from '../../utils/syntax';
import { computeValidPeriod } from './indicator-utils';
import { addFilter } from '../../utils/filtering/filtering-utils';
import type { AuthContext, AuthUser } from '../../types/user';
import { type BasicStoreEntityIndicator, ENTITY_TYPE_INDICATOR, type StoreEntityIndicator } from './indicator-types';
import {
  type EditInput,
  FilterMode,
  FilterOperator,
  type IndicatorAddInput,
  OrderingMode,
  type QueryIndicatorsArgs,
  type QueryIndicatorsNumberArgs,
  type StixCyberObservable
} from '../../generated/graphql';
import type { BasicStoreCommon, NumberResult } from '../../types/store';
import {
  computeChartDecayAlgoSerie,
  type ComputeDecayChartInput,
  computeDecayPointReactionDate,
  computeNextScoreReactionDate,
  computeScoreFromExpectedTime,
  computeScoreList,
  computeTimeFromExpectedScore,
  type DecayChartData,
  type DecayHistory,
  type DecayLiveDetails,
  findDecayRuleForIndicator
} from '../decayRule/decayRule-domain';
import { isModuleActivated } from '../../domain/settings';
import { stixDomainObjectEditField } from '../../domain/stixDomainObject';
import { prepareDate, utcDate } from '../../utils/format';
import { checkObservableValue, isCacheEmpty } from '../../database/exclusionListCache';
import { stixHashesToInput } from '../../schema/fieldDataAdapter';

export const findById = (context: AuthContext, user: AuthUser, indicatorId: string) => {
  return storeLoadById<BasicStoreEntityIndicator>(context, user, indicatorId, ENTITY_TYPE_INDICATOR);
};

export const findAll = (context: AuthContext, user: AuthUser, args: QueryIndicatorsArgs) => {
  return listEntitiesPaginated<BasicStoreEntityIndicator>(context, user, [ENTITY_TYPE_INDICATOR], args);
};

/**
 * Compute real actual value of score for an indicator.
 * @param indicator
 */
export const computeLiveScore = (indicator: BasicStoreEntityIndicator) => {
  if (indicator.decay_base_score_date && indicator.decay_base_score && indicator.decay_applied_rule) {
    const decayRule = indicator.decay_applied_rule;
    const daysSinceDecayStart = moment().diff(moment(indicator.decay_base_score_date), 'days', true);
    return Math.round(computeScoreFromExpectedTime(indicator.decay_base_score, daysSinceDecayStart, decayRule));
  }
  // by default return current score
  return indicator.x_opencti_score;
};

/**
 * Compute next expected date for reactions point of this indicator.
 * Only score in future are calculated (ie: score that are lower than actual score)
 * @param indicator
 */
export const computeLivePoints = (indicator: BasicStoreEntityIndicator) => {
  if (indicator.decay_applied_rule && indicator.decay_applied_rule.decay_points && indicator.decay_base_score_date) {
    const result: DecayHistory[] = [];
    const nextKeyPoints = [...indicator.decay_applied_rule.decay_points, indicator.decay_applied_rule.decay_revoke_score];
    for (let i = 0; i < nextKeyPoints.length; i += 1) {
      const scorePoint = nextKeyPoints[i];
      if (scorePoint < indicator.x_opencti_score) {
        const elapsedTimeInDays = computeTimeFromExpectedScore(indicator.decay_base_score, scorePoint, indicator.decay_applied_rule);
        const duration = moment.duration(elapsedTimeInDays, 'days');
        const scoreDate = moment(indicator.decay_base_score_date).add(duration.asMilliseconds(), 'ms');
        result.push({ updated_at: scoreDate.toDate(), score: scorePoint });
      }
    }
    return result;
  }
  return [];
};

/**
 * Compute live decay detail for an indicator.
 * @param context
 * @param user
 * @param indicator
 */
export const getDecayDetails = async (context: AuthContext, user: AuthUser, indicator: BasicStoreEntityIndicator) => {
  if (!indicator.decay_applied_rule) {
    return null;
  }
  const details: DecayLiveDetails = {
    live_score: computeLiveScore(indicator),
    live_points: computeLivePoints(indicator),
  };
  return details;
};

export const getDecayChartData = async (context: AuthContext, user: AuthUser, indicator: BasicStoreEntityIndicator) => {
  if (!indicator.decay_applied_rule) {
    return null;
  }
  const scoreListForChart = computeScoreList(indicator.decay_base_score);

  const chartDataInput: ComputeDecayChartInput = {
    decayBaseScore: indicator.decay_base_score,
    decayBaseScoreDate: indicator.decay_base_score_date,
    decayRule: indicator.decay_applied_rule,
    scoreList: scoreListForChart,
    decayHistory: indicator.decay_history,
  };
  const liveScoreSerie = computeChartDecayAlgoSerie(chartDataInput);

  const chartData: DecayChartData = {
    live_score_serie: liveScoreSerie,
  };
  return chartData;
};
export const findIndicatorsForDecay = (context: AuthContext, user: AuthUser, maxSize: number) => {
  const filters = {
    orderBy: 'decay_next_reaction_date',
    orderMode: OrderingMode.Asc,
    mode: FilterMode.And,
    filters: [
      { key: ['decay_next_reaction_date'], values: [prepareDate()], operator: FilterOperator.Lt },
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
  input: { objectLabel?: string[] | null; objectMarking?: string[] | null; objectOrganization?: string[] | null; createdBy?: string | null; externalReferences?: string[] | null; },
  indicator: StoreEntityIndicator,
) => {
  const { pattern } = indicator;
  const observables = extractValidObservablesFromIndicatorPattern(pattern);
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
      objectOrganization: input.objectOrganization,
      objectLabel: input.objectLabel,
      externalReferences: input.externalReferences,
      update: true,
    };
    try {
      const createdObservable: StixCyberObservable = await createEntity(context, user, observableInput, observable.type);
      observablesToLink.push(createdObservable);
    } catch (err) {
      logApp.error('[API] Create observable from indicator fail', { index, cause: err, ...extendedErrors({ input: observableInput }) });
    }
  }
  await Promise.all(
    observablesToLink.map((observableToLink) => {
      const relationInput = {
        fromId: indicator.id,
        toId: observableToLink.id,
        relationship_type: RELATION_BASED_ON,
        objectMarking: input.objectMarking,
        objectOrganization: input.objectOrganization,
      };
      return createRelation(context, user, relationInput);
    })
  );
  return observablesToLink;
};

export const promoteIndicatorToObservables = async (context: AuthContext, user: AuthUser, indicatorId: string) => {
  const indicator: StoreEntityIndicator = await storeLoadByIdWithRefs(context, user, indicatorId) as StoreEntityIndicator;
  const objectLabel = (indicator[INPUT_LABELS] ?? []).map((n) => n.internal_id);
  const objectMarking = (indicator[INPUT_MARKINGS] ?? []).map((n) => n.internal_id);
  const objectOrganization = (indicator[INPUT_GRANTED_REFS] ?? []).map((n) => n.internal_id);
  const externalReferences = (indicator[INPUT_EXTERNAL_REFS] ?? []).map((n) => n.internal_id);
  const createdBy = indicator[INPUT_CREATED_BY]?.internal_id;
  const input = { objectLabel, objectMarking, objectOrganization, createdBy, externalReferences };
  return createObservablesFromIndicator(context, user, input, indicator);
};

export const getObservableValuesFromPattern = (pattern: string) => {
  const observableValues = extractObservablesFromIndicatorPattern(pattern);
  return observableValues.map((o) => (o.hashes ? { ...o, hashes: stixHashesToInput(o) } : o));
};

const validateIndicatorPattern = async (context: AuthContext, user: AuthUser, patternType: string, patternValue: string) => {
  // check indicator syntax
  const loweredPatternType = patternType.toLowerCase();
  const formattedPattern = cleanupIndicatorPattern(loweredPatternType, patternValue);
  const check = await checkIndicatorSyntax(context, user, loweredPatternType, formattedPattern);
  if (check === false) {
    throw FunctionalError(`Indicator of type ${patternType} is not correctly formatted.`, { doc_code: 'INCORRECT_INDICATOR_FORMAT' });
  }

  // Check that indicator is not excluded from an exclusion list
  // no need to check if the exclusion list cache is empty
  if (!isCacheEmpty()) {
    const observableValues = getObservableValuesFromPattern(formattedPattern);
    for (let i = 0; i < observableValues.length; i += 1) {
      const exclusionListCheck = await checkObservableValue(observableValues[i]);
      if (exclusionListCheck) {
        throw FunctionalError(`Indicator of type ${patternType} is contained in exclusion list.`, {
          doc_code: 'INDICATOR_PATTERN_EXCLUDED',
          excludedValue: exclusionListCheck.value,
          exclusionList: exclusionListCheck.listId
        });
      }
    }
  }

  return { formattedPattern };
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

  const { formattedPattern } = await validateIndicatorPattern(context, user, indicator.pattern_type, indicator.pattern);

  const indicatorBaseScore = indicator.x_opencti_score ?? 50;
  const isDecayActivated = await isModuleActivated('INDICATOR_DECAY_MANAGER');
  // find default decay rule (even if decay is not activated, it is used to compute default validFrom and validUntil)
  const decayRule = await findDecayRuleForIndicator(context, observableType);
  const { validFrom, validUntil, revoked, validPeriod } = await computeValidPeriod(indicator, decayRule.decay_lifetime);
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
  if (isDecayActivated && !revoked) {
    const indicatorDecayRule = {
      decay_rule_id: decayRule.id,
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
    const revokeDate = computeDecayPointReactionDate(indicatorBaseScore, decayRule, validFrom, decayRule.decay_revoke_score);
    finalIndicatorToCreate = {
      ...indicatorToCreate,
      decay_next_reaction_date: nextScoreReactionDate,
      decay_base_score: indicatorBaseScore,
      decay_base_score_date: validFrom.toISOString(),
      decay_applied_rule: indicatorDecayRule,
      decay_history: decayHistory,
      valid_until: revokeDate.toISOString(),
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
      const input = {
        fromId: created.id,
        toId: observableToLink,
        relationship_type: RELATION_BASED_ON,
        objectMarking: indicator.objectMarking,
        objectOrganization: indicator.objectOrganization,
      };
      return createRelation(context, user, input);
    })
  );
  if (observablesToLink.length === 0 && indicator.createObservables) {
    await createObservablesFromIndicator(context, user, indicator, created);
  }
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

export const indicatorEditField = async (context: AuthContext, user: AuthUser, id: string, input: EditInput[], opts = {}) => {
  const finalInput = [...input];
  const indicator = await findById(context, user, id);
  if (!indicator) {
    throw FunctionalError('Cannot edit the field, Indicator cannot be found.');
  }
  // validation check because according to STIX 2.1 specification the valid_until must be greater than the valid_from
  let { valid_from, valid_until } = indicator;
  input.forEach((e) => {
    if (e.key === 'valid_from') [valid_from] = e.value;
    if (e.key === 'valid_until') [valid_until] = e.value;
  });
  if (new Date(valid_until) <= new Date(valid_from)) {
    throw ValidationError('The valid until date must be greater than the valid from date', 'valid_from');
  }
  const scoreEditInput = input.find((e) => e.key === 'x_opencti_score');
  if (scoreEditInput) {
    if (indicator.decay_applied_rule && !scoreEditInput.value.includes(indicator.decay_base_score)) {
      const newScore = scoreEditInput.value[0];
      const updateDate = utcDate();
      finalInput.push({ key: 'decay_base_score', value: [newScore] });
      finalInput.push({ key: 'decay_base_score_date', value: [updateDate.toISOString()] });
      const decayHistory: DecayHistory[] = [...(indicator.decay_history ?? [])];
      decayHistory.push({
        updated_at: updateDate.toDate(),
        score: newScore,
      });
      finalInput.push({ key: 'decay_history', value: decayHistory });
      const model = indicator.decay_applied_rule;
      const nextScoreReactionDate = computeNextScoreReactionDate(newScore, newScore, model, updateDate);
      if (nextScoreReactionDate) {
        finalInput.push({ key: 'decay_next_reaction_date', value: [nextScoreReactionDate.toISOString()] });
      }
      const newValidUntilDate = computeDecayPointReactionDate(newScore, model, updateDate, model.decay_revoke_score);
      finalInput.push({ key: 'valid_until', value: [newValidUntilDate.toISOString()] });
    }
  }
  // check indicator pattern syntax
  const patternEditInput = input.find((e) => e.key === 'pattern');
  if (patternEditInput) {
    await validateIndicatorPattern(context, user, indicator.pattern_type, patternEditInput.value[0]);
  }

  logApp.info('indicatorEditField finalInput', { finalInput });
  return stixDomainObjectEditField(context, user, id, finalInput, opts);
};

export interface IndicatorPatch {
  revoked?: boolean,
  x_opencti_score?: number,
  decay_history?: DecayHistory[],
  decay_next_reaction_date?: Date,
  x_opencti_detection?: boolean,
}

export const computeIndicatorDecayPatch = (indicator: BasicStoreEntityIndicator) => {
  let patch: IndicatorPatch = {};
  const model = indicator.decay_applied_rule;
  if (!model || !model.decay_points) {
    return null;
  }
  const newStableScore = model.decay_points.find((p) => (p || indicator.x_opencti_score) < indicator.x_opencti_score) || model.decay_revoke_score;
  if (newStableScore) {
    const decayHistory: DecayHistory[] = [...(indicator.decay_history ?? [])];
    decayHistory.push({
      updated_at: new Date(),
      score: newStableScore,
    });
    patch = {
      x_opencti_score: newStableScore,
      decay_history: decayHistory,
    };
    if (newStableScore <= model.decay_revoke_score) {
      patch = { ...patch, revoked: true, x_opencti_detection: false };
    } else {
      const nextScoreReactionDate = computeNextScoreReactionDate(indicator.decay_base_score, newStableScore, model, moment(indicator.valid_from));
      if (nextScoreReactionDate) {
        patch = { ...patch, decay_next_reaction_date: nextScoreReactionDate };
      }
    }
  }
  return patch;
};

/**
 * Triggered by the decay manager when decay_next_reaction_date is reached.
 * Compute the next step for Indicator as patch to applied to the database:
 * - change the current stable score to next
 * - update the decay_next_reaction_date to next one
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

export const observablesPaginated = async <T extends BasicStoreCommon>(context: AuthContext, user: AuthUser, indicatorId: string, args: EntityOptions<T>) => {
  return listEntitiesThroughRelationsPaginated<T>(context, user, indicatorId, RELATION_BASED_ON, ABSTRACT_STIX_CYBER_OBSERVABLE, false, args);
};
