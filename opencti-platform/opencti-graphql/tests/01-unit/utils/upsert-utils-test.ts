import { describe, expect, it } from 'vitest';
import { buildUpdatePatchForUpsert, generateAttributesInputsForUpsert, generateRefsInputsForUpsert, isDateLimitSentinel, isStoredLimitDateKeptValid } from '../../../src/utils/upsert-utils';
import { FROM_START_STR, UNTIL_END_STR } from '../../../src/utils/format';
import { ENTITY_TYPE_INDICATOR } from '../../../src/modules/indicator/indicator-types';
import { testContext } from '../../utils/testQuery';

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

  describe('on a synchronized upsert with a lower confidence', () => {
    const synchronizedContext = { ...testContext, synchronizedUpsert: true };
    const existingIndicator = {
      entity_type: ENTITY_TYPE_INDICATOR,
      standard_id: 'indicator--existing',
      confidence: 80,
      x_opencti_score: 80,
    };
    const lowerConfidence = { confidenceLevelToApply: 30, isConfidenceMatch: false, isConfidenceUpper: false };

    it('should keep the existing confidence when the input has no confidence', () => {
      const result = buildUpdatePatchForUpsert(makeUser(), existingIndicator, ENTITY_TYPE_INDICATOR, { x_opencti_main_observable_type: 'IPv4-Addr' }, lowerConfidence);
      expect(result).not.toHaveProperty('confidence');
      const inputs = generateAttributesInputsForUpsert(synchronizedContext, makeUser(), existingIndicator, ENTITY_TYPE_INDICATOR, result, lowerConfidence);
      expect(inputs.find((i) => i.key === 'confidence')).toBeUndefined();
    });

    it('should apply the input confidence when the input has a confidence', () => {
      const result = buildUpdatePatchForUpsert(makeUser(), existingIndicator, ENTITY_TYPE_INDICATOR, { confidence: 20 }, { ...lowerConfidence, confidenceLevelToApply: 20 });
      expect(result.confidence).toBe(20);
      const inputs = generateAttributesInputsForUpsert(synchronizedContext, makeUser(), existingIndicator, ENTITY_TYPE_INDICATOR, result, lowerConfidence);
      expect(inputs.find((i) => i.key === 'confidence')).toEqual({ key: 'confidence', value: [20] });
    });
  });
});

describe('generate upsert inputs - event older than the last update of the attribute', () => {
  const eventTime = Date.parse('2026-01-01T10:00:00.000Z');
  // The attributes were updated 40 seconds after the event that triggered this upsert (a long playbook run, for instance)
  const lastUpdate = new Date(eventTime + 40000).toISOString();
  const outdatedContext = { ...testContext, eventId: `${eventTime}-0` };
  const confidence = { confidenceLevelToApply: 80, isConfidenceMatch: true, isConfidenceUpper: true };
  const updatedAt = (name: string) => ({ name, updated_at: lastUpdate, confidence: 80, user_id: 'other-user' });
  const existingIndicator = {
    entity_type: ENTITY_TYPE_INDICATOR,
    standard_id: 'indicator--existing',
    confidence: 80,
    name: 'existing name',
    description: 'existing description',
    x_opencti_stix_ids: ['indicator--11111111-1111-4111-8111-111111111111'],
    'object-marking': ['marking-1'],
    'created-by': 'identity-1',
    i_attributes: [
      updatedAt('x_opencti_stix_ids'),
      updatedAt('description'),
      updatedAt('name'),
      updatedAt('objectMarking'),
      updatedAt('createdBy'),
    ],
  };

  it('should keep the stix ids consolidation', () => {
    const newStixId = 'indicator--22222222-2222-4222-8222-222222222222';
    const inputs = generateAttributesInputsForUpsert(outdatedContext, makeUser(), existingIndicator, ENTITY_TYPE_INDICATOR, { x_opencti_stix_ids: [newStixId] }, confidence);
    expect(inputs.find((i) => i.key === 'x_opencti_stix_ids')).toEqual({ key: 'x_opencti_stix_ids', value: [newStixId], operation: 'add' });
  });

  it('should discard the overwrite of a single value attribute', () => {
    const inputs = generateAttributesInputsForUpsert(outdatedContext, makeUser(), existingIndicator, ENTITY_TYPE_INDICATOR, { description: 'older description', name: 'older name' }, confidence);
    expect(inputs).toEqual([]);
  });

  it('should apply the overwrite of a single value attribute when the event is newer', () => {
    const newerContext = { ...testContext, eventId: `${eventTime + 60000}-0` };
    const inputs = generateAttributesInputsForUpsert(newerContext, makeUser(), existingIndicator, ENTITY_TYPE_INDICATOR, { description: 'newer description' }, confidence);
    expect(inputs).toEqual([{ key: 'description', value: ['newer description'] }]);
  });

  it('should keep the add of a multiple ref', () => {
    const patch = { objectMarking: [{ internal_id: 'marking-1' }, { internal_id: 'marking-2' }] };
    const inputs = generateRefsInputsForUpsert(outdatedContext, makeUser(), existingIndicator, ENTITY_TYPE_INDICATOR, patch, confidence, false);
    expect(inputs).toEqual([{ key: 'objectMarking', value: [{ internal_id: 'marking-2' }], operation: 'add' }]);
  });

  it('should discard the replace of multiple refs on a synchronized upsert', () => {
    const synchronizedContext = { ...outdatedContext, synchronizedUpsert: true };
    const patch = { objectMarking: [{ internal_id: 'marking-2' }] };
    const inputs = generateRefsInputsForUpsert(synchronizedContext, makeUser(), existingIndicator, ENTITY_TYPE_INDICATOR, patch, confidence, false);
    expect(inputs).toEqual([]);
  });

  it('should discard the overwrite of a single ref', () => {
    const patch = { createdBy: { internal_id: 'identity-2' } };
    const inputs = generateRefsInputsForUpsert(outdatedContext, makeUser(), existingIndicator, ENTITY_TYPE_INDICATOR, patch, confidence, false);
    expect(inputs).toEqual([]);
  });
});

describe('isDateLimitSentinel', () => {
  it('should flag the start sentinel on a start limit date', () => {
    expect(isDateLimitSentinel('first_seen', FROM_START_STR)).toBe(true);
    expect(isDateLimitSentinel('start_time', new Date(0))).toBe(true);
    expect(isDateLimitSentinel('valid_from', FROM_START_STR)).toBe(true);
  });

  it('should flag the end sentinel on an end limit date', () => {
    expect(isDateLimitSentinel('last_seen', UNTIL_END_STR)).toBe(true);
    expect(isDateLimitSentinel('stop_time', new Date(UNTIL_END_STR))).toBe(true);
  });

  it('should not flag a real date, an empty value, a crossed sentinel or another attribute', () => {
    expect(isDateLimitSentinel('first_seen', '2026-10-23T00:00:00.000Z')).toBe(false);
    expect(isDateLimitSentinel('first_seen', null)).toBe(false);
    expect(isDateLimitSentinel('first_seen', UNTIL_END_STR)).toBe(false);
    expect(isDateLimitSentinel('last_seen', FROM_START_STR)).toBe(false);
    expect(isDateLimitSentinel('created', FROM_START_STR)).toBe(false);
  });
});

describe('isStoredLimitDateKeptValid', () => {
  const stored = { valid_from: '2026-08-01T00:00:00.000Z', valid_until: '2026-11-13T00:00:00.000Z' };

  it('should keep the stored end date when it still bounds the period', () => {
    expect(isStoredLimitDateKeptValid('valid_until', stored, { valid_from: '2026-10-01T00:00:00.000Z', valid_until: UNTIL_END_STR })).toBe(true);
    expect(isStoredLimitDateKeptValid('valid_until', stored, { valid_until: UNTIL_END_STR })).toBe(true);
  });

  it('should not keep the stored end date when the new start date is after it (issue #19796)', () => {
    expect(isStoredLimitDateKeptValid('valid_until', stored, { valid_from: '2026-11-18T00:00:00.000Z', valid_until: UNTIL_END_STR })).toBe(false);
  });

  it('should not keep the stored start date when the new end date is before it', () => {
    expect(isStoredLimitDateKeptValid('first_seen', { first_seen: '2026-10-01T00:00:00.000Z' }, { first_seen: FROM_START_STR, last_seen: '2026-09-01T00:00:00.000Z' })).toBe(false);
  });

  it('should keep any stored date without a pair or without a stored value', () => {
    expect(isStoredLimitDateKeptValid('created', stored, {})).toBe(true);
    expect(isStoredLimitDateKeptValid('last_seen', {}, { first_seen: '2026-11-18T00:00:00.000Z', last_seen: UNTIL_END_STR })).toBe(true);
  });
});
