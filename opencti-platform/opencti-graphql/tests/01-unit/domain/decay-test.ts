import { describe, it, expect } from 'vitest';
import moment from 'moment';
import {
  BUILT_IN_DECAY_RULES,
  computeLivePoints,
  computeLiveScore,
  computeNextScoreReactionDate,
  computeScoreFromExpectedTime,
  computeTimeFromExpectedScore,
  type DecayRule,
  FALLBACK_DECAY_RULE,
  findDecayRuleForIndicator
} from '../../../src/modules/indicator/decay-domain';
import { computeIndicatorDecayPatch, type IndicatorPatch } from '../../../src/modules/indicator/indicator-domain';
import type { BasicStoreEntityIndicator } from '../../../src/modules/indicator/indicator-types';

describe('Decay formula testing', () => {
  it('should compute score', () => {
    const baseScore = 100;
    const compute20Score = computeScoreFromExpectedTime(baseScore, 20, FALLBACK_DECAY_RULE);
    expect(Math.round(compute20Score)).toBe(62);
    const compute28Score = computeScoreFromExpectedTime(baseScore, 28, FALLBACK_DECAY_RULE);
    expect(Math.round(compute28Score)).toBe(58);
    const compute31Score = computeScoreFromExpectedTime(baseScore, 31, FALLBACK_DECAY_RULE);
    expect(Math.round(compute31Score)).toBe(56);
    const compute366Score = computeScoreFromExpectedTime(baseScore, 366, FALLBACK_DECAY_RULE);
    expect(Math.round(compute366Score)).toBe(0);
    const computeBadScore = computeScoreFromExpectedTime(baseScore, -5, FALLBACK_DECAY_RULE);
    expect(Math.round(computeBadScore)).toBe(100);
  });

  it('should compute score and time', () => {
    const baseScore = 100;
    const compute20Score = computeScoreFromExpectedTime(baseScore, 20, FALLBACK_DECAY_RULE);
    expect(Math.round(computeTimeFromExpectedScore(baseScore, compute20Score, FALLBACK_DECAY_RULE))).toBe(20);
  });

  it('should find the right rule for indicator type', () => {
    // GIVEN the type is unknown or not filled, WHEN getting decay rule, THEN the FALLBACK one is return.
    let decayRule: DecayRule = findDecayRuleForIndicator('', BUILT_IN_DECAY_RULES);
    expect(decayRule.id).toBe('FALLBACK_DECAY_RULE');

    // GIVEN the type is IP, WHEN getting decay rule, THEN the IP one is return.
    decayRule = findDecayRuleForIndicator('IPv6-Addr', BUILT_IN_DECAY_RULES);
    expect(decayRule.id).toBe('IP_DECAY_RULE');

    // GIVEN the type is URL, WHEN getting decay rule, THEN the URL one is return.
    decayRule = findDecayRuleForIndicator('Url', BUILT_IN_DECAY_RULES);
    expect(decayRule.id).toBe('URL_DECAY_RULE');

    // GIVEN the type 'Url' that matched 2 rules
    const rulesWithTwoUrls: DecayRule[] = [];
    rulesWithTwoUrls.push({
      id: 'URL_DECAY_RULE_IS_LESS_IMPORTANT',
      decay_lifetime: 60,
      decay_pound: 0.33,
      decay_points: [60],
      decay_revoke_score: 0,
      indicator_types: ['Url'],
      order: 2,
      enabled: true,
    });
    rulesWithTwoUrls.push({
      id: 'URL_DECAY_RULE',
      decay_lifetime: 180,
      decay_pound: 1.0,
      decay_points: [80, 60, 40, 20],
      decay_revoke_score: 0,
      indicator_types: ['Url'],
      order: 3,
      enabled: true,
    });
    // WHEN getting decay rule
    decayRule = findDecayRuleForIndicator('Url', rulesWithTwoUrls);
    // THEN the rule is the one with lower value in order
    expect(decayRule.id, 'When several rules matches, the one with lower order value should be taken.').toBe('URL_DECAY_RULE');
  });

  it('should find the next reaction date', () => {
    const startDate = moment('2023-01-01');

    // GIVEN a decay based on fallback, WHEN stable score is the last reaction point
    let nextReactionDate = computeNextScoreReactionDate(100, 20, FALLBACK_DECAY_RULE, startDate);
    // THEN the next reaction date should be the revoke day, 1 year after the start date.
    expect((moment(nextReactionDate)).format('YYYY-MM-DD'), 'Next reaction date should be the revoke date.').toBe('2024-01-01');

    // GIVEN a decay based on fallback, WHEN stable score is the first stable score
    nextReactionDate = computeNextScoreReactionDate(100, 100, FALLBACK_DECAY_RULE, startDate);
    // THEN the next reaction date should be the one for score 80 => after 2.9 days
    expect((moment(nextReactionDate)).format('YYYY-MM-DD'), 'Next reaction date should be after two days').toBe('2023-01-03');
    const expected80ScoreDays = computeTimeFromExpectedScore(100, 80, FALLBACK_DECAY_RULE);
    expect(expected80ScoreDays).toBeCloseTo(2.9, 1);
  });
});

describe('Decay update testing', () => {
  const getDefaultIndicatorEntity = () => {
    const indicatorInput: Partial<BasicStoreEntityIndicator> = {
      x_opencti_score: 50,
      x_opencti_base_score: 100,
      x_opencti_decay_history: [],
      valid_from: moment().subtract('5', 'days').toDate(),
      valid_until: moment().add('5', 'days').toDate()
    };
    return indicatorInput as BasicStoreEntityIndicator;
  };

  const defaultDecayRule: DecayRule = {
    decay_lifetime: 30,
    decay_points: [80, 60, 20],
    decay_pound: 0.5,
    decay_revoke_score: 10,
    enabled: true,
    id: 'decay-test-next-score',
    indicator_types: [],
    order: 0
  };

  it('should move to next score and update next reaction date for default rule', () => {
    // GIVEN an Indicator with decay that is on the first decay point and has next reaction point
    const indicatorInput = getDefaultIndicatorEntity();
    indicatorInput.x_opencti_decay_rule = FALLBACK_DECAY_RULE;
    indicatorInput.x_opencti_score = 50;
    indicatorInput.x_opencti_decay_history = [{
      updated_at: indicatorInput.valid_from,
      score: 50,
    }];

    // WHEN next reaction point is computed
    const patchResult = computeIndicatorDecayPatch(indicatorInput);

    // THEN
    expect(patchResult?.revoked, 'This indicator should not be revoked.').toBeUndefined();
    expect(patchResult?.x_opencti_score, 'This indicator should be updated to next score (50 -> 40).').toBe(40);
    expect(patchResult?.next_score_reaction_date, 'This indicator should have a new reaction date.').toBeDefined();
    expect(patchResult?.x_opencti_decay_history?.length, 'This indicator should have one more history data.').toBe(2);
    expect(patchResult?.x_opencti_decay_history?.at(1)?.score, 'This indicator should have one more history data.').toBe(40);
  });

  it('should move to next score and update next reaction date', () => {
    // GIVEN an Indicator with decay that is on the first decay point and has next reaction point
    const indicatorInput = getDefaultIndicatorEntity();
    indicatorInput.x_opencti_decay_rule = defaultDecayRule;
    indicatorInput.x_opencti_decay_rule.decay_points = [100, 80, 50, 20];
    indicatorInput.x_opencti_decay_rule.decay_revoke_score = 10;
    indicatorInput.x_opencti_score = 100;
    indicatorInput.x_opencti_decay_history = [];

    // WHEN next reaction point is computed
    const patchResult = computeIndicatorDecayPatch(indicatorInput);

    // THEN
    expect(patchResult?.revoked, 'This indicator should not be revoked.').toBeUndefined();
    expect(patchResult?.x_opencti_score, 'This indicator should be updated to next score (100 -> 80).').toBe(80);
    expect(patchResult?.next_score_reaction_date, 'This indicator should have a new reaction date.').toBeDefined();
    expect(patchResult?.x_opencti_decay_history?.length, 'This indicator should have one more history data.').toBe(1);
    expect(patchResult?.x_opencti_decay_history?.at(0)?.score, 'This indicator should have one more history data.').toBe(80);
  });

  it('should be revoked when revoke score is reached', () => {
    // GIVEN an Indicator with decay that is on the last decay point and has next a revoke score
    const indicatorInput = getDefaultIndicatorEntity();
    indicatorInput.x_opencti_decay_rule = defaultDecayRule;
    indicatorInput.x_opencti_decay_rule.decay_points = [100, 80, 50, 20];
    indicatorInput.x_opencti_decay_rule.decay_revoke_score = 10;
    indicatorInput.x_opencti_score = 20;
    indicatorInput.x_opencti_decay_history = [];
    indicatorInput.x_opencti_decay_history.push({ updated_at: new Date(2023, 1), score: 100 });

    // WHEN next reaction point is computed
    const patchResult = computeIndicatorDecayPatch(indicatorInput);

    // THEN
    expect(patchResult?.revoked, 'This indicator should be revoked.').toBeTruthy();
    expect(patchResult?.x_opencti_score, 'This indicator should be updated to revoke score.').toBe(10);
    expect(patchResult?.next_score_reaction_date, 'This indicator should not have a next reaction date.').toBeUndefined();
    expect(patchResult?.x_opencti_decay_history?.length, 'This indicator should have one more history data.').toBe(2);
  });

  it('should revoke when current score is already lower than revoke score', () => {
    // GIVEN an Indicator with a stable score that is already lower than revoke score
    // use case that should not happen with a normal usage
    const indicatorInput = getDefaultIndicatorEntity();
    indicatorInput.x_opencti_decay_rule = defaultDecayRule;
    indicatorInput.x_opencti_decay_rule.decay_points = [100, 80, 50, 20];
    indicatorInput.x_opencti_decay_rule.decay_revoke_score = 50;
    indicatorInput.x_opencti_score = 30;

    // WHEN next reaction point is computed
    const patchResult = computeIndicatorDecayPatch(indicatorInput);

    // THEN
    expect(patchResult?.revoked, 'This indicator should be revoked.').toBeTruthy();
    expect(patchResult?.x_opencti_score, 'This indicator should be updated to revoke score.').toBe(20);
    expect(patchResult?.next_score_reaction_date, 'This indicator should not have a next reaction date.').toBeUndefined();
  });

  it('should revoke when revoke score is higher than all decay points', () => {
    // GIVEN an Indicator with revoke score higher than all decay points
    // use case that should not happen with a normal usage
    const indicatorInput = getDefaultIndicatorEntity();
    indicatorInput.x_opencti_decay_rule = defaultDecayRule;
    indicatorInput.x_opencti_decay_rule.decay_points = [80, 50, 20];
    indicatorInput.x_opencti_decay_rule.decay_revoke_score = 100;
    indicatorInput.x_opencti_score = 50;

    // WHEN next reaction point is computed
    const patchResult = computeIndicatorDecayPatch(indicatorInput) as IndicatorPatch;

    // THEN
    expect(patchResult.revoked, 'This indicator should be revoked.').toBeTruthy();
    expect(patchResult.x_opencti_score, 'This indicator should be updated to revoke score.').toBe(20);
    expect(patchResult.next_score_reaction_date, 'This indicator should not have a next reaction date.').toBeUndefined();
  });

  it('should do nothing when decay rule is null', () => {
    // GIVEN an Indicator with no decay rule
    const indicatorInput = getDefaultIndicatorEntity();

    // WHEN next reaction point is computed
    const patchResult = computeIndicatorDecayPatch(indicatorInput) as IndicatorPatch;

    // THEN
    expect(patchResult, 'No database operation should be done.').toBeNull();
  });
});

describe('Decay live detailed data testing (subset of indicatorDecayDetails query)', () => {
  it('should compute live score correctly', () => {
    const indicator: Partial<BasicStoreEntityIndicator> = {
      x_opencti_score: 100,
      x_opencti_base_score: 100,
      x_opencti_base_score_date: moment().subtract('5', 'days').toDate(),
      x_opencti_decay_rule: FALLBACK_DECAY_RULE,
      valid_from: moment().subtract('5', 'days').toDate(),
      valid_until: moment().add('5', 'days').toDate()
    };

    const liveScore = computeLiveScore(indicator as BasicStoreEntityIndicator);
    expect(liveScore).toBe(76);
  });

  it('should live score be equals to stable when x_opencti_base_score_date is missing', () => {
    const indicator: Partial<BasicStoreEntityIndicator> = {
      x_opencti_score: 42,
      x_opencti_base_score: 100,
      x_opencti_base_score_date: undefined,
      x_opencti_decay_history: [],
      valid_from: moment().subtract('5', 'days').toDate(),
      valid_until: moment().add('5', 'days').toDate()
    };
    const liveScore = computeLiveScore(indicator as BasicStoreEntityIndicator);
    expect(liveScore, 'The live score should be = score when data required for computation are missing.').toBe(42);
  });

  it('should next reaction point be updated when score is lower than max reaction score', () => {
    const indicator: Partial<BasicStoreEntityIndicator> = {
      x_opencti_score: 42,
      x_opencti_base_score: 100,
      x_opencti_base_score_date: moment().subtract('5', 'days').toDate(),
      x_opencti_decay_history: [],
      x_opencti_decay_rule: FALLBACK_DECAY_RULE,
      valid_from: moment().subtract('5', 'days').toDate(),
      valid_until: moment().add('5', 'days').toDate()
    };

    const result = computeLivePoints(indicator as BasicStoreEntityIndicator);
    expect(result[0].score, 'The live score should be = score when data required for computation are missing.').toBe(40);
  });
});
