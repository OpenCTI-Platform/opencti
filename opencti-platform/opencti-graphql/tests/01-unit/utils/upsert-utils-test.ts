import { describe, expect, it } from 'vitest';
import { buildUpdatePatchForUpsert } from '../../../src/utils/upsert-utils';
import { ENTITY_TYPE_INDICATOR } from '../../../src/modules/indicator/indicator-types';

const makeUser = () => ({
  id: 'test-user',
  no_creators: true,
});

describe('buildUpdatePatchForUpsert - indicator confidence gating', () => {
  it('should preserve lifecycle and metadata fields when confidence is lower', () => {
    const existingIndicator = {
      entity_type: ENTITY_TYPE_INDICATOR,
      standard_id: 'indicator--existing',
      confidence: 70,
      x_opencti_score: 70,
      valid_from: '2024-01-01T00:00:00.000Z',
      valid_until: '2024-03-01T00:00:00.000Z',
      revoked: true,
      decay_base_score: 70,
      decay_base_score_date: '2024-01-01T00:00:00.000Z',
      decay_applied_rule: { decay_rule_id: 'rule-existing' },
      decay_exclusion_applied_rule: undefined,
      decay_history: [{ score: 70, updated_by: 'source-a', updated_at: '2024-01-01T00:00:00.000Z' }],
      decay_next_reaction_date: '2024-01-15T00:00:00.000Z',
    };
    const incomingPatch = {
      confidence: 50,
      x_opencti_score: 80,
      valid_from: '2025-01-01T00:00:00.000Z',
      valid_until: '2025-04-01T00:00:00.000Z',
      revoked: false,
      decay_base_score: 80,
      decay_base_score_date: '2025-01-01T00:00:00.000Z',
      decay_applied_rule: { decay_rule_id: 'rule-new' },
      decay_history: [{ score: 80, updated_by: 'source-b', updated_at: '2025-01-01T00:00:00.000Z' }],
      decay_next_reaction_date: '2025-01-15T00:00:00.000Z',
    };

    const result = buildUpdatePatchForUpsert(
      makeUser(),
      existingIndicator,
      ENTITY_TYPE_INDICATOR,
      incomingPatch,
      { confidenceLevelToApply: 50, isConfidenceMatch: false, isConfidenceUpper: false },
    );

    expect(result.x_opencti_score).toBe(existingIndicator.x_opencti_score);
    expect(result.valid_from).toBe(existingIndicator.valid_from);
    expect(result.valid_until).toBe(existingIndicator.valid_until);
    expect(result.revoked).toBe(existingIndicator.revoked);
    expect(result.decay_base_score).toBe(existingIndicator.decay_base_score);
    expect(result.decay_base_score_date).toBe(existingIndicator.decay_base_score_date);
    expect(result.decay_applied_rule).toEqual(existingIndicator.decay_applied_rule);
    expect(result.decay_next_reaction_date).toBe(existingIndicator.decay_next_reaction_date);
    expect(result).not.toHaveProperty('decay_history');
    expect(result.confidence).toBe(50);
  });

  it('should keep incoming indicator lifecycle and metadata fields when confidence is sufficient', () => {
    const existingIndicator = {
      entity_type: ENTITY_TYPE_INDICATOR,
      standard_id: 'indicator--existing',
      confidence: 70,
      x_opencti_score: 70,
      valid_from: '2024-01-01T00:00:00.000Z',
      valid_until: '2024-03-01T00:00:00.000Z',
      revoked: true,
    };
    const incomingPatch = {
      confidence: 80,
      x_opencti_score: 80,
      valid_from: '2025-01-01T00:00:00.000Z',
      valid_until: '2025-04-01T00:00:00.000Z',
      revoked: false,
      decay_base_score: 80,
      decay_base_score_date: '2025-01-01T00:00:00.000Z',
      decay_applied_rule: { decay_rule_id: 'rule-new' },
      decay_history: [{ score: 80, updated_by: 'source-b', updated_at: '2025-01-01T00:00:00.000Z' }],
      decay_next_reaction_date: '2025-01-15T00:00:00.000Z',
    };

    const result = buildUpdatePatchForUpsert(
      makeUser(),
      existingIndicator,
      ENTITY_TYPE_INDICATOR,
      incomingPatch,
      { confidenceLevelToApply: 80, isConfidenceMatch: true, isConfidenceUpper: true },
    );

    expect(result.x_opencti_score).toBe(incomingPatch.x_opencti_score);
    expect(result.valid_from).toBe(incomingPatch.valid_from);
    expect(result.valid_until).toBe(incomingPatch.valid_until);
    expect(result.revoked).toBe(incomingPatch.revoked);
    expect(result.decay_base_score).toBe(incomingPatch.decay_base_score);
    expect(result.decay_base_score_date).toBe(incomingPatch.decay_base_score_date);
    expect(result.decay_applied_rule).toEqual(incomingPatch.decay_applied_rule);
    expect(result.decay_history).toEqual(incomingPatch.decay_history);
    expect(result.decay_next_reaction_date).toBe(incomingPatch.decay_next_reaction_date);
    expect(result.confidence).toBe(80);
  });
});
