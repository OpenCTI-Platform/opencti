import { describe, expect, it, vi } from 'vitest';
import { isPirMatchableOnStream } from '../../../src/manager/pirManager';
import type { ParsedPir } from '../../../src/modules/pir/pir-types';
import { PirType } from '../../../src/generated/graphql';
import { testContext } from '../../utils/testQuery';

// The custom field testers are read from the cache, not available in unit tests: no custom field is defined.
vi.mock('../../../src/modules/customField/custom-field-stix-utils', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../src/modules/customField/custom-field-stix-utils')>(),
  getCustomFieldsStixFilterTesters: async () => ({}),
}));

const buildPir = (criterionFilterKey: string) => ({
  id: `pir-${criterionFilterKey}`,
  pir_type: PirType.ThreatLandscape,
  pir_filters: {
    mode: 'and',
    filters: [{ key: ['confidence'], values: ['50'], operator: 'gte', mode: 'or' }],
    filterGroups: [],
  },
  pir_criteria: [{
    weight: 1,
    filters: {
      mode: 'and',
      filters: [
        { key: ['entity_type'], values: ['targets'], operator: 'eq', mode: 'or' },
        { key: [criterionFilterKey], values: ['location-id'], operator: 'eq', mode: 'or' },
      ],
      filterGroups: [],
    },
  }],
} as unknown as ParsedPir);

describe('Pir manager', () => {
  describe('Function isPirMatchableOnStream()', () => {
    it('should accept a Pir built like the UI does', async () => {
      expect(await isPirMatchableOnStream(testContext, buildPir('toId'))).toBe(true);
    });

    it('should accept a Pir with a filter on a deleted custom field, as stix matching does', async () => {
      expect(await isPirMatchableOnStream(testContext, buildPir('x_opencti_cf_deleted'))).toBe(true);
    });

    it('should reject a Pir with a filter key not supported in stix matching', async () => {
      expect(await isPirMatchableOnStream(testContext, buildPir('regardingOf'))).toBe(false);
    });
  });
});
