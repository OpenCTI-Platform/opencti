import { describe, expect, it } from 'vitest';
import { PirCreationFormData, pirFormDataToMutationInput } from './pir-form-utils';

describe('PIR form utils', () => {
  describe('pirFormDataToMutationInput()', () => {
    const baseData: PirCreationFormData = {
      name: 'Super PIR',
      pir_type: 'THREAT_LANDSCAPE',
      description: 'Super description',
      pir_rescan_days: 30,
      confidence: 80,
      locations: [{ label: 'FR', value: 'fr' }, { label: 'EN', value: 'en' }],
      sectors: [{ label: 'Energy', value: 'energy' }],
    };

    it('should transform data correctly', () => {
      expect(pirFormDataToMutationInput(baseData)).toEqual({
        name: 'Super PIR',
        pir_type: 'THREAT_LANDSCAPE',
        description: 'Super description',
        pir_rescan_days: 30,
        pir_criteria: [
          {
            weight: 1,
            filters: {
              mode: 'and',
              filterGroups: [],
              filters: [
                { key: ['entity_type'], values: ['targets'], operator: 'eq', mode: 'or' },
                { key: ['toId'], values: ['fr'], operator: 'eq', mode: 'or' },
              ],
            },
          },
          {
            weight: 1,
            filters: {
              mode: 'and',
              filterGroups: [],
              filters: [
                { key: ['entity_type'], values: ['targets'], operator: 'eq', mode: 'or' },
                { key: ['toId'], values: ['en'], operator: 'eq', mode: 'or' },
              ],
            },
          },
          {
            weight: 1,
            filters: {
              mode: 'and',
              filterGroups: [],
              filters: [
                { key: ['entity_type'], values: ['targets'], operator: 'eq', mode: 'or' },
                { key: ['toId'], values: ['energy'], operator: 'eq', mode: 'or' },
              ],
            },
          },
        ],
        pir_filters: {
          mode: 'and',
          filterGroups: [],
          filters: [{
            key: ['confidence'],
            values: ['80'],
            operator: 'gte',
            mode: 'or',
          }],
        },
      });
    });

    it('should not set description if empty', () => {
      const input = pirFormDataToMutationInput({
        ...baseData,
        description: '',
      });
      expect(input.description).toEqual(undefined);
    });

    it('should have 0 for confidence if null', () => {
      const input = pirFormDataToMutationInput({
        ...baseData,
        confidence: null,
      });
      expect(input.pir_filters).toEqual({
        mode: 'and',
        filterGroups: [],
        filters: [{
          key: ['confidence'],
          values: ['0'],
          operator: 'gte',
          mode: 'or',
        }],
      });
    });
  });
});
