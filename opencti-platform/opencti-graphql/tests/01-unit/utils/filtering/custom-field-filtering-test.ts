import { describe, it, expect, beforeEach } from 'vitest';
import { adaptFilterToCustomFieldFilterKey } from '../../../../src/utils/filtering/filtering-completeSpecialFilterKeys';
import { isCustomFieldFilterKey, isComplexConversionFilterKey } from '../../../../src/utils/filtering/filtering-constants';
import { setCustomFieldDefinitionsCache } from '../../../../src/modules/customField/custom-field-cache';
import { FilterOperator } from '../../../../src/generated/graphql';
import type { BasicStoreEntityCustomFieldDefinition } from '../../../../src/modules/customField/custom-field-types';
import type { Filter } from '../../../../src/generated/graphql';

const makeDefinition = (overrides: Partial<BasicStoreEntityCustomFieldDefinition> = {}): BasicStoreEntityCustomFieldDefinition => ({
  id: 'cf-id-1',
  standard_id: 'custom-field-definition--id-1',
  entity_type: 'CustomFieldDefinition',
  name: 'x_opencti_cf_field',
  label: 'Field',
  description: '',
  field_type: 'string',
  entity_types: ['Case-Incident'],
  entity_type_settings: [],
  multiple: false,
  ...overrides,
} as unknown as BasicStoreEntityCustomFieldDefinition);

const makeFilter = (overrides: Partial<Filter> = {}): Filter => ({
  key: ['x_opencti_cf_field'],
  values: ['test'],
  operator: FilterOperator.Eq,
  mode: 'or',
  ...overrides,
} as Filter);

describe('isCustomFieldFilterKey', () => {
  it('returns true for keys starting with the custom field prefix', () => {
    expect(isCustomFieldFilterKey('x_opencti_cf_score')).toBe(true);
    expect(isCustomFieldFilterKey('x_opencti_cf_')).toBe(true);
  });

  it('returns false for regular filter keys', () => {
    expect(isCustomFieldFilterKey('name')).toBe(false);
    expect(isCustomFieldFilterKey('entity_type')).toBe(false);
    expect(isCustomFieldFilterKey('objectMarking')).toBe(false);
    expect(isCustomFieldFilterKey('x_opencti_score')).toBe(false);
  });
});

describe('isComplexConversionFilterKey — custom field integration', () => {
  it('considers a custom field key as a complex conversion key', () => {
    expect(isComplexConversionFilterKey('x_opencti_cf_score')).toBe(true);
  });

  it('does not affect non-custom-field keys that are not already complex', () => {
    expect(isComplexConversionFilterKey('name')).toBe(false);
    expect(isComplexConversionFilterKey('description')).toBe(false);
  });
});

describe('adaptFilterToCustomFieldFilterKey', () => {
  beforeEach(() => {
    setCustomFieldDefinitionsCache([]);
  });

  it('throws when the definition is not found in the cache', () => {
    setCustomFieldDefinitionsCache([]);
    const filter = makeFilter({ key: ['x_opencti_cf_unknown'] });
    expect(() => adaptFilterToCustomFieldFilterKey(filter)).toThrow('Custom field definition not found for filter key');
  });

  describe('string fields', () => {
    beforeEach(() => {
      setCustomFieldDefinitionsCache([makeDefinition({ name: 'x_opencti_cf_field', field_type: 'string' })]);
    });

    it('produces a nested filter scoped to field_name + string_value', () => {
      const { newFilter, newFilterGroup } = adaptFilterToCustomFieldFilterKey(makeFilter({ values: ['hello'] }));
      expect(newFilterGroup).toBeUndefined();
      expect(newFilter.key).toEqual(['custom_field_values']);
      expect(newFilter.nested).toEqual(expect.arrayContaining([
        { key: 'field_name', values: ['x_opencti_cf_field'], operator: FilterOperator.Eq },
        { key: 'string_value', values: ['hello'], operator: FilterOperator.Eq },
      ]));
    });

    it('passes through non-eq operators on string fields unchanged', () => {
      const { newFilter } = adaptFilterToCustomFieldFilterKey(
        makeFilter({ values: ['prefix'], operator: FilterOperator.StartsWith }),
      );
      expect(newFilter.nested).toEqual(expect.arrayContaining([
        { key: 'string_value', values: ['prefix'], operator: FilterOperator.StartsWith },
      ]));
    });
  });

  describe('boolean fields', () => {
    beforeEach(() => {
      setCustomFieldDefinitionsCache([makeDefinition({ name: 'x_opencti_cf_field', field_type: 'boolean' })]);
    });

    it('uses boolean_value as the nested value field', () => {
      const { newFilter } = adaptFilterToCustomFieldFilterKey(makeFilter({ values: ['true'] }));
      expect(newFilter.nested).toEqual(expect.arrayContaining([
        { key: 'boolean_value', values: ['true'], operator: FilterOperator.Eq },
      ]));
    });
  });

  describe('date fields', () => {
    beforeEach(() => {
      setCustomFieldDefinitionsCache([makeDefinition({ name: 'x_opencti_cf_field', field_type: 'date' })]);
    });

    it('uses date_value as the nested value field', () => {
      const { newFilter } = adaptFilterToCustomFieldFilterKey(makeFilter({ values: ['2026-01-01T00:00:00.000Z'] }));
      expect(newFilter.nested).toEqual(expect.arrayContaining([
        { key: 'date_value', values: ['2026-01-01T00:00:00.000Z'], operator: FilterOperator.Eq },
      ]));
    });
  });

  describe('select fields', () => {
    beforeEach(() => {
      setCustomFieldDefinitionsCache([makeDefinition({ name: 'x_opencti_cf_field', field_type: 'select', select_options: ['a', 'b'] })]);
    });

    it('uses select_value as the nested value field', () => {
      const { newFilter } = adaptFilterToCustomFieldFilterKey(makeFilter({ values: ['a'] }));
      expect(newFilter.nested).toEqual(expect.arrayContaining([
        { key: 'select_value', values: ['a'], operator: FilterOperator.Eq },
      ]));
    });
  });

  describe('multi_select fields', () => {
    beforeEach(() => {
      setCustomFieldDefinitionsCache([makeDefinition({ name: 'x_opencti_cf_field', field_type: 'multi_select', select_options: ['a', 'b'] })]);
    });

    it('uses select_values as the nested value field', () => {
      const { newFilter } = adaptFilterToCustomFieldFilterKey(makeFilter({ values: ['a', 'b'] }));
      expect(newFilter.nested).toEqual(expect.arrayContaining([
        { key: 'select_values', values: ['a', 'b'], operator: FilterOperator.Eq },
      ]));
    });
  });

  describe('integer fields — special eq range logic', () => {
    beforeEach(() => {
      setCustomFieldDefinitionsCache([makeDefinition({ name: 'x_opencti_cf_field', field_type: 'integer' })]);
    });

    it('translates eq to gte+lte range for exact integer match', () => {
      const { newFilter } = adaptFilterToCustomFieldFilterKey(makeFilter({ values: ['42'], operator: FilterOperator.Eq }));
      expect(newFilter.nested).toEqual(expect.arrayContaining([
        { key: 'int_value', values: [42], operator: FilterOperator.Gte },
        { key: 'int_value', values: [42], operator: FilterOperator.Lte },
      ]));
      // field_name discriminant is always present
      expect(newFilter.nested).toEqual(expect.arrayContaining([
        { key: 'field_name', values: ['x_opencti_cf_field'], operator: FilterOperator.Eq },
      ]));
    });

    it('parses numeric string values to numbers for eq operator', () => {
      const { newFilter } = adaptFilterToCustomFieldFilterKey(makeFilter({ values: ['7'], operator: FilterOperator.Eq }));
      const gtClause = newFilter.nested?.find((n: any) => n.operator === FilterOperator.Gte);
      expect(gtClause?.values).toEqual([7]);
    });

    it('uses a single int_value clause for non-eq operators (e.g. gte)', () => {
      const { newFilter } = adaptFilterToCustomFieldFilterKey(makeFilter({ values: ['10'], operator: FilterOperator.Gte }));
      const intClauses = newFilter.nested?.filter((n: any) => n.key === 'int_value');
      expect(intClauses).toHaveLength(1);
      expect(intClauses?.[0]).toMatchObject({ key: 'int_value', values: [10], operator: FilterOperator.Gte });
    });

    it('produces an empty values array at the root level of the nested filter', () => {
      const { newFilter } = adaptFilterToCustomFieldFilterKey(makeFilter({ values: ['5'] }));
      expect(newFilter.values).toEqual([]);
    });

    it('targets custom_field_values as the root key', () => {
      const { newFilter } = adaptFilterToCustomFieldFilterKey(makeFilter({ values: ['1'] }));
      expect(newFilter.key).toEqual(['custom_field_values']);
    });
  });

  describe('key provided as a string (not array)', () => {
    it('extracts the key from a plain string instead of an array', () => {
      setCustomFieldDefinitionsCache([makeDefinition({ name: 'x_opencti_cf_field', field_type: 'string' })]);
      const filter = { ...makeFilter(), key: 'x_opencti_cf_field' as unknown as string[] };
      const { newFilter } = adaptFilterToCustomFieldFilterKey(filter);
      expect(newFilter.nested).toEqual(expect.arrayContaining([
        { key: 'field_name', values: ['x_opencti_cf_field'], operator: FilterOperator.Eq },
      ]));
    });
  });

  describe('markdown fields (reuse string_value channel)', () => {
    it('uses string_value for markdown type', () => {
      setCustomFieldDefinitionsCache([makeDefinition({ name: 'x_opencti_cf_field', field_type: 'markdown' })]);
      const { newFilter } = adaptFilterToCustomFieldFilterKey(makeFilter({ values: ['# Title'] }));
      expect(newFilter.nested).toEqual(expect.arrayContaining([
        { key: 'string_value', values: ['# Title'], operator: FilterOperator.Eq },
      ]));
    });
  });
});
