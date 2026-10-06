import { describe, expect, it } from 'vitest';
import { isPirMatchableOnStream } from '../../../src/manager/pirManager';
import type { ParsedPir } from '../../../src/modules/pir/pir-types';
import { PirType } from '../../../src/generated/graphql';

const buildPir = (criterionFilterKey: string) => ({
  id: 'pir-id',
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
    it('should accept a Pir built like the UI does', () => {
      expect(isPirMatchableOnStream(buildPir('toId'))).toBe(true);
    });

    it('should reject a Pir with a filter key not supported in stix matching', () => {
      expect(isPirMatchableOnStream(buildPir('regardingOf'))).toBe(false);
    });
  });
});
