import moment from 'moment';
import type { Moment } from 'moment';
import type { BasicStoreEntityIndicator } from './indicator-types';

export interface DecayHistory {
  updated_at: Date
  score: number
}
export interface DecayRule {
  id: string
  decay_lifetime: number // in days
  decay_pound: number // can be changed in other model when feature is ready.
  decay_points: number[] // reactions points
  decay_revoke_score: number // revoked when score is <= 20
  indicator_types: string[] // x_opencti_main_observable_type
  order: number // low priority = 0
  enabled: boolean
}

export interface DecayLiveDetails {
  live_score: number
  live_points: DecayHistory[]
}

/** This is the model used when no configured decay model matches for an Indicator.
 * It's also the default one if nothing is configured yet. */
export const FALLBACK_DECAY_RULE: DecayRule = {
  id: 'FALLBACK_DECAY_RULE',
  decay_lifetime: 365, // 1 year
  decay_pound: 1.0,
  decay_points: [80, 60, 40, 20],
  decay_revoke_score: 0,
  indicator_types: [],
  order: 0,
  enabled: true,
};
export const IP_DECAY_RULE: DecayRule = {
  id: 'IP_DECAY_RULE',
  decay_lifetime: 60,
  decay_pound: 1.0,
  decay_points: [80, 60, 40, 20],
  decay_revoke_score: 0,
  indicator_types: ['IPv4-Addr', 'IPv6-Addr'],
  order: 1,
  enabled: true,
};
export const URL_DECAY_RULE: DecayRule = {
  id: 'URL_DECAY_RULE',
  decay_lifetime: 180,
  decay_pound: 1.0,
  decay_points: [80, 60, 40, 20],
  decay_revoke_score: 0,
  indicator_types: ['Url'],
  order: 1,
  enabled: true,
};
export const BUILT_IN_DECAY_RULES = [
  IP_DECAY_RULE, URL_DECAY_RULE, FALLBACK_DECAY_RULE,
];

const DECAY_FACTOR: number = 3.0;

/**
 * Calculate the indicator score at a time (in days). With polynomial implementation (MISP approach).
 * @param initialScore initial indicator score, usually between 100 and 0.
 * @param daysFromStart elapsed time in days since the start point.
 * @param rule decay configuration to use.
 */
export const computeScoreFromExpectedTime = (initialScore: number, daysFromStart: number, rule: DecayRule) => {
  if (!rule) {
    return initialScore;
  }
  if (daysFromStart > rule.decay_lifetime) return 0;
  if (daysFromStart <= 0) return initialScore;
  return initialScore * (1 - ((daysFromStart / rule.decay_lifetime) ** (1 / (DECAY_FACTOR * rule.decay_pound))));
};

/**
 * Calculate the elapsed time (in days) from start data to get a score value. With polynomial implementation (MISP approach)
 * @param initialScore initial indicator score, usually between 100 and 0.
 * @param score the score value requested to calculate time
 * @param model decay configuration to use.
 */
export const computeTimeFromExpectedScore = (initialScore: number, score: number, model: DecayRule) => {
  if (model.decay_pound && model.decay_lifetime) {
    return (Math.E ** (Math.log(1 - (score / initialScore)) * (DECAY_FACTOR * model.decay_pound))) * model.decay_lifetime;
  }
  return 0;
};

export const computeNextScoreReactionDate = (initialScore: number, stableScore: number, model: DecayRule, startDate: Moment) => {
  if (model.decay_points && model.decay_points.length > 0) {
    const nextKeyPoint = model.decay_points.find((p) => p < stableScore) || model.decay_revoke_score;
    const daysDelay = computeTimeFromExpectedScore(initialScore, nextKeyPoint, model);
    const duration = moment.duration(daysDelay, 'days');
    return moment(startDate).add(duration.asMilliseconds(), 'ms').toDate();
  }
  return null;
};

export const findDecayRuleForIndicator = (indicatorObservableType: string, enabledRules: DecayRule[]) => {
  if (!indicatorObservableType) {
    return FALLBACK_DECAY_RULE;
  }
  const orderedRules = [...enabledRules].sort((a, b) => (b.order || 0) - (a.order || 0));
  const decayRule = orderedRules.find((rule) => rule.indicator_types?.includes(indicatorObservableType) || rule.indicator_types?.length === 0);
  return decayRule || FALLBACK_DECAY_RULE;
};

/**
 * Compute real actual value of score for an indicator.
 * @param indicator
 */
export const computeLiveScore = (indicator: BasicStoreEntityIndicator) => {
  if (indicator.decay_base_score_date && indicator.decay_base_score && indicator.decay_applied_rule) {
    const decayRule = indicator.decay_applied_rule as DecayRule;
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
        const elapsedTimeInDays = computeTimeFromExpectedScore(indicator.decay_base_score, scorePoint, indicator.decay_applied_rule as DecayRule);
        const duration = moment.duration(elapsedTimeInDays, 'days');
        const scoreDate = moment(indicator.decay_base_score_date).add(duration.asMilliseconds(), 'ms');
        result.push({ updated_at: scoreDate.toDate(), score: scorePoint });
      }
    }
    return result;
  }
  return [];
};
