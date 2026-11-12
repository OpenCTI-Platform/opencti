import { describe, expect, it } from 'vitest';
import moment from 'moment';
import { computeIndicatorDecayOnCreation } from '../../../../src/modules/indicator/indicator-domain';
import { computeDecayPointReactionDate } from '../../../../src/modules/decayRule/decayRule-domain';

const VALID_FROM = moment('2026-01-01T00:00:00.000Z');
const BASE_SCORE = 80;
const USER_ID = 'test-user-id';

const RULE_WITH_POINTS = {
  id: 'rule-with-points',
  decay_lifetime: 365,
  decay_pound: 1,
  decay_points: [60, 40],
  decay_revoke_score: 20,
};

describe('computeIndicatorDecayOnCreation', () => {
  it('should apply the rule reaction points', () => {
    const result = computeIndicatorDecayOnCreation(RULE_WITH_POINTS, BASE_SCORE, VALID_FROM, USER_ID);

    expect(result.decay_applied_rule).toEqual({
      decay_rule_id: 'rule-with-points',
      decay_lifetime: 365,
      decay_pound: 1,
      decay_points: [60, 40],
      decay_revoke_score: 20,
    });
    expect(result.decay_applied_rule.decay_points).not.toBe(RULE_WITH_POINTS.decay_points);
    expect(result.decay_base_score).toBe(BASE_SCORE);
    expect(result.decay_base_score_date).toBe(VALID_FROM.toISOString());
    expect(result.decay_history).toEqual([{ updated_at: VALID_FROM.toDate(), score: BASE_SCORE, updated_by: USER_ID }]);
    expect(result.decay_next_reaction_date).toEqual(computeDecayPointReactionDate(BASE_SCORE, RULE_WITH_POINTS, VALID_FROM, 60));
    expect(result.valid_until).toBe(computeDecayPointReactionDate(BASE_SCORE, RULE_WITH_POINTS, VALID_FROM, 20).toISOString());
  });

  it('should decay straight to the revoke score when the rule has no reaction points', () => {
    const { decay_points: _, ...ruleWithoutPoints } = RULE_WITH_POINTS;

    const result = computeIndicatorDecayOnCreation(ruleWithoutPoints, BASE_SCORE, VALID_FROM, USER_ID);

    expect(result.decay_applied_rule.decay_points).toEqual([]);
    expect(result.decay_next_reaction_date).toBeNull();
    expect(result.valid_until).toBe(computeDecayPointReactionDate(BASE_SCORE, RULE_WITH_POINTS, VALID_FROM, 20).toISOString());
  });

  it('should handle a rule with an empty list of reaction points', () => {
    const result = computeIndicatorDecayOnCreation({ ...RULE_WITH_POINTS, decay_points: [] }, BASE_SCORE, VALID_FROM, USER_ID);

    expect(result.decay_applied_rule.decay_points).toEqual([]);
    expect(result.decay_next_reaction_date).toBeNull();
    expect(result.valid_until).toBe(computeDecayPointReactionDate(BASE_SCORE, RULE_WITH_POINTS, VALID_FROM, 20).toISOString());
  });
});
