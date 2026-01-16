import moment, { type Moment } from 'moment/moment';
import type { AuthContext, AuthUser } from '../../types/user';
import { countAllThings, fullEntitiesList, pageEntitiesConnection, storeLoadById } from '../../database/middleware-loader';
import type { DecayRuleAddInput, EditInput, QueryDecayRulesArgs } from '../../generated/graphql';
import { FilterMode } from '../../generated/graphql';
import { type BasicStoreEntityDecayRule, ENTITY_TYPE_DECAY_RULE, type StoreEntityDecayRule } from './decayRule-types';
import { createInternalObject } from '../../domain/internalObject';
import { now } from '../../utils/format';
import { getEntitiesListFromCache } from '../../database/cache';
import { READ_INDEX_STIX_DOMAIN_OBJECTS } from '../../database/utils';
import { SYSTEM_USER } from '../../utils/access';
import { FunctionalError } from '../../config/errors';
import { deleteElementById, updateAttribute } from '../../database/middleware';
import { publishUserAction } from '../../listener/UserActionListener';
import { BUS_TOPICS } from '../../config/conf';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { notify } from '../../database/redis';
import {
  ENTITY_DOMAIN_NAME,
  ENTITY_HASHED_OBSERVABLE_ARTIFACT,
  ENTITY_HASHED_OBSERVABLE_STIX_FILE,
  ENTITY_IPV4_ADDR,
  ENTITY_IPV6_ADDR,
  ENTITY_URL,
} from '../../schema/stixCyberObservable';

const DECAY_FACTOR: number = 3.0;

export interface DecayChartData {
  live_score_serie: DecayHistoryChart[];
}

export interface DecayModel {
  decay_lifetime: number; // in days
  decay_pound: number; // can be changed in other model when feature is ready.
  decay_points: number[]; // reactions points
  decay_revoke_score: number; // revoked when score is <= 20
}

export interface DecayRuleConfiguration extends DecayModel {
  id?: string;
  name: string;
  description: string;
  decay_observable_types: string[]; // x_opencti_main_observable_type
  order: number; // low priority = 0
  active: boolean;
}

export interface ComputeDecayChartInput {
  scoreList: number[];
  decayBaseScore: number;
  decayBaseScoreDate: Date;
  decayRule: DecayModel;
  decayHistory: DecayHistoryChart[];
}

// for storage on elastic
export interface DecayHistory {
  updated_at: Date;
  score: number;
  updated_by: string;
}

export interface DecayHistoryChart {
  updated_at: Date;
  score: number;
}

export interface DecayLiveDetails {
  live_score: number;
  live_points: DecayHistoryChart[];
}

export const dayToMs = (days: number) => {
  return days * 24 * 60 * 60 * 1000;
};

export const findById = (context: AuthContext, user: AuthUser, id: string) => {
  return storeLoadById<BasicStoreEntityDecayRule>(context, user, id, ENTITY_TYPE_DECAY_RULE);
};

export const findDecayRulePaginated = (context: AuthContext, user: AuthUser, args: QueryDecayRulesArgs) => {
  return pageEntitiesConnection<BasicStoreEntityDecayRule>(context, user, [ENTITY_TYPE_DECAY_RULE], args);
};

export const addDecayRule = async (context: AuthContext, user: AuthUser, input: DecayRuleAddInput, builtIn?: boolean) => {
  const defaultOps = {
    created_at: now(),
    updated_at: now(),
    active: input.active || false,
    built_in: builtIn || false,
  };

  if (input.decay_points) {
    input.decay_points.sort().reverse();

    // cannot use array.filter on a read-only array.
    for (let i = input.decay_points.length - 1; i >= 0; i -= 1) {
      if (input.decay_points[i] < 0) {
        input.decay_points.splice(i, 1);
      }
    }
  }

  const decayRuleInput = { ...input, ...defaultOps };
  return createInternalObject<StoreEntityDecayRule>(context, user, decayRuleInput, ENTITY_TYPE_DECAY_RULE);
};

export const fieldPatchDecayRule = async (context: AuthContext, user: AuthUser, id: string, input: EditInput[]) => {
  const finalInput = [...input];
  const decayRule = await findById(context, user, id);
  if (!decayRule) {
    throw FunctionalError(`Decay rule ${id} cannot be found`);
  }
  if (decayRule.built_in) {
    throw FunctionalError(`Cannot update built-in decay rule ${id}`);
  }

  const decayPointsInput = finalInput.find((editInput) => editInput.key === 'decay_points');
  if (decayPointsInput) {
    decayPointsInput.value.sort().reverse();

    // cannot use array.filter on a read-only array.
    for (let i = decayPointsInput.value.length - 1; i >= 0; i -= 1) {
      if (decayPointsInput.value[i] < 0) {
        decayPointsInput.value.splice(i, 1);
      }
    }
  }

  const { element } = await updateAttribute<StoreEntityDecayRule>(context, user, id, ENTITY_TYPE_DECAY_RULE, finalInput);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `updates \`${input.map((i) => i.key).join(', ')}\` for decay rule \`${element.name}\``,
    context_data: { id, entity_type: ENTITY_TYPE_DECAY_RULE, input },
  });
  return notify(BUS_TOPICS[ENTITY_TYPE_DECAY_RULE].EDIT_TOPIC, element, user);
};

export const deleteDecayRule = async (context: AuthContext, user: AuthUser, id: string) => {
  const decayRule = await findById(context, user, id);
  if (!decayRule) {
    throw FunctionalError(`Decay rule ${id} cannot be found`);
  }
  if (decayRule.built_in) {
    throw FunctionalError(`Cannot delete built-in decay rule ${id}`);
  }
  const deleted = await deleteElementById<StoreEntityDecayRule>(context, user, id, ENTITY_TYPE_DECAY_RULE);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'delete',
    event_access: 'administration',
    message: `deletes decay rule \`${deleted.name}\``,
    context_data: { id, entity_type: ENTITY_TYPE_DECAY_RULE, input: deleted },
  });
  await notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].DELETE_TOPIC, decayRule, user);
  return id;
};

export const countAppliedIndicators = async (context: AuthContext, user: AuthUser, decayRule: BasicStoreEntityDecayRule) => {
  return countAllThings(context, user, {
    indices: [READ_INDEX_STIX_DOMAIN_OBJECTS],
    filters: {
      mode: FilterMode.And,
      filters: [
        { key: ['entity_type'], values: ['Indicator'] }, // TODO fix cyclic dep with ENTITY_TYPE_INDICATOR
        { key: ['revoked'], values: ['false'] },
        { key: ['decay_applied_rule.decay_rule_id'], values: [decayRule.id] },
      ],
      filterGroups: [],
    },
  });
};

/**
 * Compute all time scores needed to draw the chart from base score to 0.
 */
export const computeScoreList = (maxScore: number): number[] => {
  const scoreArray: number[] = [];
  for (let i = maxScore; i >= 0; i -= 1) {
    scoreArray.push(i);
  }
  return scoreArray;
};

/**
 * Calculate the elapsed time (in days) from start data to get a score value. With polynomial implementation (MISP approach)
 * @param initialScore initial indicator score, usually between 100 and 0.
 * @param score the score value requested to calculate time
 * @param model decay configuration to use.
 */
export const computeTimeFromExpectedScore = (initialScore: number, score: number, model: DecayModel) => {
  if (initialScore === 0) { // Can't divide by 0 when the initial score is 0
    return 0;
  }
  if (model.decay_pound && model.decay_lifetime) {
    return (Math.E ** (Math.log(1 - (score / initialScore)) * (DECAY_FACTOR * model.decay_pound))) * model.decay_lifetime;
  }
  return 0;
};

/**
 * Compute all data point (x as time, y as score value) needed to draw the decay mathematical curve as time serie.
 * If Decay has been reset, add point before current decay start date.
 * @param computeChartInput all data required to compute the decay curve
 * @param userId
 */
export const computeChartDecayAlgoSerie = (computeChartInput: ComputeDecayChartInput): DecayHistoryChart[] => {
  if (computeChartInput) {
    const decayData: DecayHistoryChart[] = [];
    const startDateInMs = moment(computeChartInput.decayBaseScoreDate).valueOf();
    computeChartInput.scoreList.forEach((scoreValue) => {
      const timeForScore = dayToMs(computeTimeFromExpectedScore(computeChartInput.decayBaseScore, scoreValue, computeChartInput.decayRule));
      const point: DecayHistoryChart = { updated_at: moment(startDateInMs + timeForScore).toDate(), score: scoreValue };
      decayData.push(point);
    });

    // When decay has been reset, we add stable score before the start point of last decay.
    if (computeChartInput.decayHistory && computeChartInput.decayHistory.length > 0) {
      const orderedDecayHistoryAsc = [...computeChartInput.decayHistory];

      let i = 0;
      const scoreInThePast: DecayHistoryChart[] = [];
      while ((orderedDecayHistoryAsc[i].updated_at < computeChartInput.decayBaseScoreDate) && i < orderedDecayHistoryAsc.length) {
        const historyPointToProcess = orderedDecayHistoryAsc[i];
        scoreInThePast.push({ updated_at: historyPointToProcess.updated_at, score: historyPointToProcess.score });
        if (i + 1 < orderedDecayHistoryAsc.length) {
          scoreInThePast.push({ updated_at: orderedDecayHistoryAsc[i + 1].updated_at, score: historyPointToProcess.score });
        }
        i += 1;
      }
      decayData.unshift(...scoreInThePast);
    }
    return decayData;
  }
  return [];
};

export const getDecaySettingsChartData = async (context: AuthContext, user: AuthUser, decayRule: BasicStoreEntityDecayRule) => {
  const scoreListForChart = computeScoreList(100);
  const chartCurveData: ComputeDecayChartInput = {
    decayBaseScore: 100,
    decayBaseScoreDate: new Date(),
    decayRule: decayRule as DecayModel,
    scoreList: scoreListForChart,
    decayHistory: [],
  };
  const liveScoreSerie = computeChartDecayAlgoSerie(chartCurveData);

  const chartData: DecayChartData = {
    live_score_serie: liveScoreSerie,
  };
  return chartData;
};

// region init built-in decay rules
export const FALLBACK_DECAY_RULE: DecayRuleConfiguration = {
  name: 'Built-in default',
  description: 'Built-in decay rule for all indicators that do not match any other decay rule.',
  decay_lifetime: 470, // 1 year
  decay_pound: 0.35,
  decay_points: [80, 50],
  decay_revoke_score: 20,
  decay_observable_types: [], // Matches all
  order: 0,
  active: true,
};
export const BUILT_IN_DECAY_RULE_FILE_ARTEFACT: DecayRuleConfiguration = {
  name: 'Built-in files and artifact',
  description: 'Built-in decay rule for indicators with files or artefact as main observable type.',
  decay_lifetime: 460,
  decay_pound: 0.3,
  decay_points: [80],
  decay_revoke_score: 20,
  decay_observable_types: [
    ENTITY_HASHED_OBSERVABLE_STIX_FILE,
    ENTITY_HASHED_OBSERVABLE_ARTIFACT,
  ],
  order: 1,
  active: true,
};

export const BUILT_IN_DECAY_RULE_IP_URL: DecayRuleConfiguration = {
  name: 'Built-in IP and URL',
  description: 'Built-in decay rule for indicators with IP or URL as main observable type.',
  decay_lifetime: 47,
  decay_pound: 0.55,
  decay_points: [80, 50],
  decay_revoke_score: 20,
  decay_observable_types: [
    ENTITY_IPV4_ADDR,
    ENTITY_IPV6_ADDR,
    ENTITY_URL,
  ],
  order: 1,
  active: true,
};

export const BUILT_IN_DECAY_RULE_DOMAIN_NAME: DecayRuleConfiguration = {
  name: 'Built-in domain name',
  description: 'Built-in decay rule for indicators with domain name as main observable type.',
  decay_lifetime: 300,
  decay_pound: 0.7,
  decay_points: [80, 50],
  decay_revoke_score: 20,
  decay_observable_types: [
    ENTITY_DOMAIN_NAME,
  ],
  order: 1,
  active: true,
};

export const BUILT_IN_DECAY_RULES = [
  BUILT_IN_DECAY_RULE_DOMAIN_NAME,
  BUILT_IN_DECAY_RULE_IP_URL,
  BUILT_IN_DECAY_RULE_FILE_ARTEFACT,
  FALLBACK_DECAY_RULE,
];

/**
 * Check on start if built-in decay rule are in the database. If not add them.
 * @param context
 * @param user
 */
export const initDecayRules = async (context: AuthContext, user: AuthUser) => {
  const args = {
    filters: {
      mode: 'and' as FilterMode,
      filters: [{ key: ['built_in'], values: [true] }],
      filterGroups: [],
    },
  };
  const currentBuiltInDecayRules = await fullEntitiesList<BasicStoreEntityDecayRule>(context, user, [ENTITY_TYPE_DECAY_RULE], args);
  if (currentBuiltInDecayRules.length === 0) {
    // no built-in decay rule, we should create the default ones
    const defaultDecayRules = [...BUILT_IN_DECAY_RULES];
    for (let index = 0; index < defaultDecayRules.length; index += 1) {
      const decayRule = defaultDecayRules[index];
      await addDecayRule(context, user, decayRule, true);
    }
  }
};

// end region
export const selectDecayRuleForIndicator = (indicatorObservableType: string, decayRules: DecayRuleConfiguration[]) => {
  const orderedRules = [...decayRules].filter((d) => d.active)
    .sort((a, b) => (b.order || 0) - (a.order || 0));
  const decayRule = orderedRules.find((rule) => {
    if (rule.decay_observable_types?.length > 0) {
      // return first rule matching the indicator main observable type
      return indicatorObservableType && rule.decay_observable_types.includes(indicatorObservableType);
    }
    return true; // return first rule
  });
  if (!decayRule) {
    // always return a fallback decay rule
    return { ...FALLBACK_DECAY_RULE, id: 'FALLBACK_DECAY_RULE' };
  }
  return decayRule;
};

export const findDecayRuleForIndicator = async (context: AuthContext, indicatorObservableType: string) => {
  const enabledRules = await getEntitiesListFromCache<BasicStoreEntityDecayRule>(context, SYSTEM_USER, ENTITY_TYPE_DECAY_RULE);
  return selectDecayRuleForIndicator(indicatorObservableType, enabledRules);
};

// region decay compute

/**
 * Calculate the indicator score at a time (in days). With polynomial implementation (MISP approach).
 * @param initialScore initial indicator score, usually between 100 and 0.
 * @param daysFromStart elapsed time in days since the start point.
 * @param rule decay configuration to use.
 */
export const computeScoreFromExpectedTime = (initialScore: number, daysFromStart: number, rule: DecayModel) => {
  if (!rule) {
    return initialScore;
  }
  if (daysFromStart > rule.decay_lifetime) return 0;
  if (daysFromStart <= 0) return initialScore;
  return initialScore * (1 - ((daysFromStart / rule.decay_lifetime) ** (1 / (DECAY_FACTOR * rule.decay_pound))));
};

export const computeDecayPointReactionDate = (initialScore: number, model: DecayModel, startDate: Moment, decayPoint: number) => {
  const daysDelay = computeTimeFromExpectedScore(initialScore, decayPoint, model);
  const duration = moment.duration(daysDelay, 'days');
  return moment(startDate).add(duration.asMilliseconds(), 'ms').toDate();
};

export const computeNextScoreReactionDate = (initialScore: number, stableScore: number, model: DecayModel, startDate: Moment) => {
  if (model.decay_points && model.decay_points.length > 0) {
    const nextKeyPoint = model.decay_points.find((p) => p < stableScore) || model.decay_revoke_score;
    return computeDecayPointReactionDate(initialScore, model, startDate, nextKeyPoint);
  }
  return null;
};
