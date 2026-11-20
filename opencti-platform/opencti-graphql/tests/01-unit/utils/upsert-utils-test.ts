import { describe, expect, it } from 'vitest';
import { buildUpdatePatchForUpsert, generateAttributesInputsForUpsert } from '../../../src/utils/upsert-utils';
import { ENTITY_TYPE_INDICATOR } from '../../../src/modules/indicator/indicator-types';
import { testContext } from '../../utils/testQuery';
import { ENTITY_TYPE_CONTAINER_REPORT, ENTITY_TYPE_INTRUSION_SET } from '../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../../src/modules/organization/organization-types';

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

describe('generateAttributesInputsForUpsert - name of an aliased entity', () => {
  const existingIntrusionSet = {
    entity_type: ENTITY_TYPE_INTRUSION_SET,
    name: 'APT-NAME-A',
    aliases: ['APT-NAME-B'],
    confidence: 50,
  };
  const equalConfidence = { confidenceLevelToApply: 50, isConfidenceMatch: true, isConfidenceUpper: false };
  const upperConfidence = { confidenceLevelToApply: 80, isConfidenceMatch: true, isConfidenceUpper: true };
  const nameInput = (context: typeof testContext, element: object, type: string, name: string, confidence: object) => {
    const inputs = generateAttributesInputsForUpsert(context, makeUser(), element, type, { name }, confidence);
    return inputs.find((i: { key: string }) => i.key === 'name');
  };

  it('should not swap the name for one of its aliases at equal confidence', () => {
    expect(nameInput(testContext, existingIntrusionSet, ENTITY_TYPE_INTRUSION_SET, 'APT-NAME-B', equalConfidence)).toBeUndefined();
  });

  it('should not swap the name for the same name written differently at equal confidence', () => {
    expect(nameInput(testContext, existingIntrusionSet, ENTITY_TYPE_INTRUSION_SET, 'apt-name-a', equalConfidence)).toBeUndefined();
  });

  it('should swap the name for one of its aliases at strictly upper confidence', () => {
    expect(nameInput(testContext, existingIntrusionSet, ENTITY_TYPE_INTRUSION_SET, 'APT-NAME-B', upperConfidence)).toEqual({ key: 'name', value: ['APT-NAME-B'] });
  });

  it('should replace the name with an unknown name at equal confidence', () => {
    expect(nameInput(testContext, existingIntrusionSet, ENTITY_TYPE_INTRUSION_SET, 'APT-NAME-C', equalConfidence)).toEqual({ key: 'name', value: ['APT-NAME-C'] });
  });

  it('should swap the name for one of its aliases on a synchronized upsert', () => {
    const synchronizedContext = { ...testContext, synchronizedUpsert: true };
    expect(nameInput(synchronizedContext, existingIntrusionSet, ENTITY_TYPE_INTRUSION_SET, 'APT-NAME-B', equalConfidence)).toEqual({ key: 'name', value: ['APT-NAME-B'] });
  });

  it('should protect the name of an identity against its x_opencti_aliases', () => {
    const existingOrganization = { entity_type: ENTITY_TYPE_IDENTITY_ORGANIZATION, name: 'ORG-NAME-A', x_opencti_aliases: ['ORG-NAME-B'], confidence: 50 };
    expect(nameInput(testContext, existingOrganization, ENTITY_TYPE_IDENTITY_ORGANIZATION, 'ORG-NAME-B', equalConfidence)).toBeUndefined();
  });

  it('should replace the name of a non aliased entity at equal confidence', () => {
    const existingReport = { entity_type: ENTITY_TYPE_CONTAINER_REPORT, name: 'REPORT-NAME-A', confidence: 50 };
    expect(nameInput(testContext, existingReport, ENTITY_TYPE_CONTAINER_REPORT, 'report-name-a', equalConfidence)).toEqual({ key: 'name', value: ['report-name-a'] });
  });
});
