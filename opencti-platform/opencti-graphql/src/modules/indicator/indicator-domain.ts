import * as R from 'ramda';
import moment from 'moment/moment';
import { createEntity, createRelation, distributionEntities, inputResolveRefs, patchAttribute, storeLoadByIdWithRefs, timeSeriesEntities } from '../../database/middleware';
import { type EntityOptions, fullEntitiesList, pageEntitiesConnection, pageRegardingEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
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
  INPUT_MARKINGS,
} from '../../schema/general';
import { elCount } from '../../database/engine';
import { isEmptyField, READ_INDEX_STIX_DOMAIN_OBJECTS } from '../../database/utils';
import { cleanupIndicatorPattern, extractObservablesFromIndicatorPattern, extractValidObservablesFromIndicatorPattern } from '../../utils/syntax';
import { computeValidPeriod, hasSameSourceAlreadyUpdateThisScore, INDICATOR_DEFAULT_SCORE, isDecayEnabled } from './indicator-utils';
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
  type StixCyberObservable,
} from '../../generated/graphql';
import type { BasicStoreEntity, NumberResult } from '../../types/store';
import {
  computeChartDecayAlgoSerie,
  type ComputeDecayChartInput,
  computeDecayPointReactionDate,
  computeNextScoreReactionDate,
  computeScoreFromExpectedTime,
  computeScoreList,
  computeTimeFromExpectedScore,
  dayToMs,
  type DecayChartData,
  type DecayHistoryChart,
  type DecayHistory,
  type DecayLiveDetails,
  findDecayRuleForIndicator,
} from '../decayRule/decayRule-domain';
import { stixDomainObjectEditField } from '../../domain/stixDomainObject';
import { checkScore, prepareDate, utcDate } from '../../utils/format';
import { checkObservableValue, isCacheEmpty } from '../../database/exclusionListCache';
import { stixHashesToInput } from '../../schema/fieldDataAdapter';
import { REVOKED, VALID_FROM, VALID_UNTIL, X_DETECTION, X_SCORE } from '../../schema/identifier';
import { checkDecayExclusionRules, getActiveDecayExclusionRules } from '../decayRule/exclusions/decayExclusionRule-domain';
import { getEntitySettingFromCache } from '../../modules/entitySetting/entitySetting-utils';
import type { BasicStoreEntityEntitySetting } from '../entitySetting/entitySetting-types';

export const NO_DECAY_DEFAULT_VALID_PERIOD: number = dayToMs(90);
export const NO_DECAY_DEFAULT_REVOKED_SCORE: number = 0;

export const findById = (context: AuthContext, user: AuthUser, indicatorId: string) => {
  return storeLoadById<BasicStoreEntityIndicator>(context, user, indicatorId, ENTITY_TYPE_INDICATOR);
};

export const findIndicatorPaginated = (context: AuthContext, user: AuthUser, args: QueryIndicatorsArgs) => {
  return pageEntitiesConnection<BasicStoreEntityIndicator>(context, user, [ENTITY_TYPE_INDICATOR], args);
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
    const result: DecayHistoryChart[] = [];
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
  return fullEntitiesList<BasicStoreEntityIndicator>(context, user, [ENTITY_TYPE_INDICATOR], args);
};

export const createObservablesFromIndicator = async (
  context: AuthContext,
  user: AuthUser,
  input: { objectLabel?: string[] | null; objectMarking?: string[] | null; objectOrganization?: string[] | null; createdBy?: string | null; externalReferences?: string[] | null },
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
    }),
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

export const getObservableValuesFromPattern = (pattern: string, rawFormat = false) => {
  const observableValues = extractObservablesFromIndicatorPattern(pattern);
  if (rawFormat) {
    return observableValues;
  }
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
          exclusionList: exclusionListCheck.listId,
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
  if (!isKnownObservable && indicator.pattern_type.toLowerCase() === 'yara') {
    observableType = 'StixFile';
  }
  if (isKnownObservable && !isStixCyberObservable(observableType)) {
    throw FunctionalError(`Observable type ${observableType} is not supported.`);
  }

  const { formattedPattern } = await validateIndicatorPattern(context, user, indicator.pattern_type, indicator.pattern);

  const indicatorBaseScore = indicator.x_opencti_score ?? INDICATOR_DEFAULT_SCORE;
  checkScore(indicatorBaseScore);

  // find default decay rule (even if decay is not activated, it is used to compute default validFrom and validUntil)
  const decayRule = await findDecayRuleForIndicator(context, observableType);

  const { validFrom, validUntil, revoked, validPeriod } = await computeValidPeriod(indicator, decayRule.decay_lifetime);

  const baseIndicator = {
    ...indicator,
    pattern: formattedPattern,
    x_opencti_main_observable_type: observableType,
    [X_SCORE]: indicatorBaseScore,
    x_opencti_detection: indicator.x_opencti_detection ?? false,
    valid_from: validFrom.toISOString(),
    valid_until: validUntil.toISOString(),
    revoked,
  };
  delete baseIndicator.basedOn;
  delete baseIndicator.createObservables;

  const isDecayActivated: boolean = await isDecayEnabled();

  const activeDecayExclusionRuleList = await getActiveDecayExclusionRules(context, user);
  const entitySetting = await getEntitySettingFromCache(context, ENTITY_TYPE_INDICATOR);
  const resolvedIndicator = await inputResolveRefs(context, user, baseIndicator, ENTITY_TYPE_INDICATOR, entitySetting as BasicStoreEntityEntitySetting);
  const exclusionRule = await checkDecayExclusionRules(context, user, resolvedIndicator, activeDecayExclusionRuleList);
  const indicatorToCreate = { ...resolvedIndicator };

  let finalIndicatorToCreate;

  if (isDecayActivated && exclusionRule) {
    finalIndicatorToCreate = {
      ...indicatorToCreate,
      decay_exclusion_applied_rule: {
        decay_exclusion_id: exclusionRule.id,
        decay_exclusion_name: exclusionRule.name,
        decay_exclusion_created_at: exclusionRule.created_at,
        decay_exclusion_filters: exclusionRule.decay_exclusion_filters,
      },
    };
  } else if (isDecayActivated && !revoked) {
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
      updated_by: user.id,
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
    }),
  );
  if (observablesToLink.length === 0 && indicator.createObservables) {
    await createObservablesFromIndicator(context, user, indicator, created);
  }
  return notify(BUS_TOPICS[ABSTRACT_STIX_DOMAIN_OBJECT].ADDED_TOPIC, created, user);
};

export const MAX_DECAY_HISTORY_POINTS = 50;
export const computeIndicatorDecayHistory = (currentHistory: DecayHistory[], newHistoryPoint: DecayHistory) => {
  const newHistory = currentHistory;
  newHistory.push(newHistoryPoint);
  // If decay history length is too large, we need to trim it to keep it at a manageable size in ES
  // we want to keep part of the start of the history, and part of the end of the history
  if (newHistory.length > MAX_DECAY_HISTORY_POINTS) {
    const startPointsToKeep = MAX_DECAY_HISTORY_POINTS / 2;
    const endPointsToKeep = MAX_DECAY_HISTORY_POINTS - startPointsToKeep;
    const startPoints = newHistory.slice(0, startPointsToKeep);
    const endPoints = newHistory.slice(-endPointsToKeep);
    return [...startPoints, ...endPoints];
  }
  return newHistory;
};

/**
 * Compute decay data when it's needed from indicator updates.
 * Return keys for 'decay_history', 'decay_next_reaction_date', 'valid_until'
 * @param fromScore
 * @param indicatorBeforeUpdate
 * @param userId
 */
export const restartDecayComputationOnEdit = (fromScore: number, indicatorBeforeUpdate: BasicStoreEntityIndicator, userId: string): EditInput[] => {
  const indicatorDecayRule = indicatorBeforeUpdate.decay_applied_rule;
  const nowDate = new Date();
  const inputToAdd: EditInput[] = [];
  const updateDate = utcDate();
  inputToAdd.push({ key: 'decay_base_score', value: [fromScore] });
  inputToAdd.push({ key: 'decay_base_score_date', value: [updateDate.toISOString()] });
  const newDecayHistoryPoint = { updated_at: nowDate, score: fromScore, updated_by: userId };
  const decayHistory = computeIndicatorDecayHistory([...(indicatorBeforeUpdate.decay_history ?? [])], newDecayHistoryPoint);
  inputToAdd.push({ key: 'decay_history', value: decayHistory });
  const nextScoreReactionDate = computeNextScoreReactionDate(fromScore, fromScore, indicatorDecayRule, updateDate);
  if (nextScoreReactionDate) {
    inputToAdd.push({ key: 'decay_next_reaction_date', value: [nextScoreReactionDate.toISOString()] });
  }

  const newValidUntil = utcDate().add(indicatorDecayRule.decay_lifetime, 'days');
  inputToAdd.push({ key: VALID_UNTIL, value: [newValidUntil.toISOString()] });

  return inputToAdd;
};

export const indicatorEditField = async (context: AuthContext, user: AuthUser, id: string, input: EditInput[], opts = {}) => {
  // Region Validation
  const indicatorBeforeUpdate = await findById(context, user, id);
  if (!indicatorBeforeUpdate) {
    throw FunctionalError('Cannot edit the field, Indicator cannot be found.', { id });
  }
  // validation check because according to STIX 2.1 specification the valid_until must be greater than the valid_from
  let { valid_from, valid_until } = indicatorBeforeUpdate;
  const validUntilEditInput = input.find((e) => e.key === VALID_UNTIL);
  const validFromEditInput = input.find((e) => e.key === VALID_FROM);

  input.forEach((e) => {
    if (e.key === VALID_FROM) [valid_from] = e.value;
    if (e.key === VALID_UNTIL) [valid_until] = e.value;
  });

  if (validUntilEditInput || validFromEditInput) {
    if (new Date(valid_until) < new Date(valid_from)) {
      throw ValidationError('The valid until date must be greater than the valid from date', VALID_FROM, { input, valid_from, valid_until });
    }
  }

  // check indicator pattern syntax
  const patternEditInput = input.find((e) => e.key === 'pattern');
  if (patternEditInput) {
    await validateIndicatorPattern(context, user, indicatorBeforeUpdate.pattern_type, patternEditInput.value[0]);
  }
  const scoreEditInput = input.find((e) => e.key === X_SCORE);
  if (scoreEditInput) {
    const newScore = scoreEditInput.value[0];
    checkScore(newScore);
  }
  // END Region Validation

  // Region Decay and {Score, Valid until, Revoke} computation
  // We keep everything EXCEPT fields that can be changed by decay computation
  const finalInput = input.filter((editInput) => {
    return editInput.key !== VALID_UNTIL && editInput.key !== X_SCORE && editInput.key !== REVOKED;
  });

  const isDecayEnabledOnIndicator: boolean = indicatorBeforeUpdate.decay_applied_rule !== undefined && indicatorBeforeUpdate.decay_applied_rule.decay_revoke_score !== undefined;

  const revokedEditInput = input.find((e) => e.key === REVOKED);
  const nowDate = new Date();
  let hasRevokedChangedToTrue: boolean = false;
  let hasRevokedChangedToFalse: boolean = false;

  // Revoke value is taken only if valid until and score are not updated at the same time too.
  if (revokedEditInput && !validUntilEditInput && !scoreEditInput) {
    hasRevokedChangedToTrue = revokedEditInput.value[0] === true && !indicatorBeforeUpdate.revoked;
    hasRevokedChangedToFalse = revokedEditInput.value[0] === false && indicatorBeforeUpdate.revoked;
    finalInput.push(revokedEditInput);
  }

  if (validUntilEditInput) {
    const untilDateTime = utcDate(validUntilEditInput?.value[0]).toDate();
    if (untilDateTime < nowDate && !indicatorBeforeUpdate.revoked) {
      finalInput.push({ key: REVOKED, value: [true] });
      hasRevokedChangedToTrue = true;
    }

    if (untilDateTime > nowDate && indicatorBeforeUpdate.revoked) {
      finalInput.push({ key: REVOKED, value: [false] });
      hasRevokedChangedToFalse = true;
    }
  }

  if (isDecayEnabledOnIndicator) {
    const revokeScore = indicatorBeforeUpdate.decay_applied_rule.decay_revoke_score;
    const baseScore = indicatorBeforeUpdate.decay_base_score;

    // Check if score is in input, unless it's the original score
    // Only if there is no valid until in input too
    if (scoreEditInput && !scoreEditInput.value.includes(baseScore) && !validUntilEditInput) {
      const newScore = scoreEditInput.value[0];
      // First check if the same update by the same source exists
      if (!hasSameSourceAlreadyUpdateThisScore(user.id, newScore, indicatorBeforeUpdate.decay_history)) {
        const allChanges = restartDecayComputationOnEdit(newScore, indicatorBeforeUpdate, user.id);
        finalInput.push(...allChanges);
        finalInput.push({ key: X_SCORE, value: [newScore] });
      }
    } else {
      // score has not been changed, but maybe decay need to be computed again anyway
      if (hasRevokedChangedToTrue) {
        finalInput.push({ key: X_SCORE, value: [revokeScore] });
        finalInput.push({ key: X_DETECTION, value: [false] });
        finalInput.push({ key: VALID_UNTIL, value: [nowDate.toISOString()] });

        const newDecayHistoryPoint = { updated_at: nowDate, score: revokeScore, updated_by: user.id };
        const decayHistory = computeIndicatorDecayHistory([...(indicatorBeforeUpdate.decay_history ?? [])], newDecayHistoryPoint);
        finalInput.push({ key: 'decay_history', value: decayHistory });
      }

      if (hasRevokedChangedToFalse) {
        logApp.debug('Indicator revoked moved to false', { id: indicatorBeforeUpdate.id });
        // Restart decay as if the score has been put to decay_base_score manually.
        const newScore = indicatorBeforeUpdate.decay_base_score;
        const allChanges = restartDecayComputationOnEdit(newScore, indicatorBeforeUpdate, user.id);
        finalInput.push(...allChanges);
        finalInput.push({ key: X_SCORE, value: [newScore] });
      }
    }
  } else {
    // No decay on indicator
    if (hasRevokedChangedToTrue) {
      finalInput.push({ key: X_SCORE, value: [NO_DECAY_DEFAULT_REVOKED_SCORE] });
      finalInput.push({ key: X_DETECTION, value: [false] });
      finalInput.push({ key: VALID_UNTIL, value: [nowDate.toISOString()] });
    }

    if (hasRevokedChangedToFalse) {
      const in90Days = new Date(nowDate.getTime() + NO_DECAY_DEFAULT_VALID_PERIOD);
      finalInput.push({ key: X_SCORE, value: [INDICATOR_DEFAULT_SCORE] });
      finalInput.push({ key: VALID_UNTIL, value: [in90Days.toISOString()] });
      finalInput.push({ key: VALID_FROM, value: [nowDate.toISOString()] });
    }
  }

  // Safeguard: if the field has in input and not added by decay computation, keep the input.
  if (validUntilEditInput && !finalInput.find((e) => e.key === VALID_UNTIL)) {
    finalInput.push(validUntilEditInput);
  }

  if (revokedEditInput && !finalInput.find((e) => e.key === REVOKED)) {
    finalInput.push(revokedEditInput);
  }
  logApp.debug('Indicator full computed changes:', { finalInput });

  // END Decay and {Score, Valid until, Revoke} computation
  if (finalInput.length > 0) {
    return stixDomainObjectEditField(context, user, id, finalInput, opts);
  }

  // If no changes because of some above rules, return the unchanged indicator
  return indicatorBeforeUpdate;
};

export interface IndicatorPatch {
  revoked?: boolean;
  x_opencti_score?: number;
  decay_history?: DecayHistory[];
  decay_next_reaction_date?: Date;
  x_opencti_detection?: boolean;
}

export const computeIndicatorDecayPatch = (context: AuthContext, user: AuthUser, indicator: BasicStoreEntityIndicator) => {
  let patch: IndicatorPatch | undefined;
  const model = indicator.decay_applied_rule;
  if (!model || !model.decay_points) {
    return null;
  }
  const newStableScore = model.decay_points.find((p) => (p || indicator.x_opencti_score) < indicator.x_opencti_score) || model.decay_revoke_score;
  if (newStableScore) {
    const newDecayHistoryPoint: DecayHistory = { updated_at: new Date(), score: newStableScore, updated_by: user.id };
    const decayHistory = computeIndicatorDecayHistory([...(indicator.decay_history ?? [])], newDecayHistoryPoint);
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
  const patch = computeIndicatorDecayPatch(context, user, indicator);
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
    types: [ENTITY_TYPE_INDICATOR],
  }) as Promise<number>;
  const totalPromise = elCount(
    context,
    user,
    READ_INDEX_STIX_DOMAIN_OBJECTS,
    { ...R.dissoc('endDate', args), types: [ENTITY_TYPE_INDICATOR] },
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
    { ...args, types: [ENTITY_TYPE_INDICATOR], filters },
  );
  const totalPromise = elCount(
    context,
    user,
    READ_INDEX_STIX_DOMAIN_OBJECTS,
    { ...R.dissoc('endDate', args), types: [ENTITY_TYPE_INDICATOR], filters },
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

export const observablesPaginated = async <T extends BasicStoreEntity>(context: AuthContext, user: AuthUser, indicatorId: string, args: EntityOptions<T>) => {
  return pageRegardingEntitiesConnection<T>(context, user, indicatorId, RELATION_BASED_ON, ABSTRACT_STIX_CYBER_OBSERVABLE, false, args);
};
