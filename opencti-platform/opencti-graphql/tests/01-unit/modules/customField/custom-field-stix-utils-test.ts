import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as cacheModule from '../../../../src/database/cache';
import * as BooleanLogicEngine from '../../../../src/utils/filtering/boolean-logic-engine';
import {
  buildCustomFieldStixFilterTester,
  flattenCustomFieldValuesForStix,
  getCustomFieldsStixFilterTesters,
  getStixCustomFieldValue,
  unflattenStixToCustomFieldValues,
} from '../../../../src/modules/customField/custom-field-stix-utils';
import type { BasicStoreEntityCustomFieldDefinition, CustomFieldValue } from '../../../../src/modules/customField/custom-field-types';
import { FilterOperator } from '../../../../src/generated/graphql';

vi.mock('../../../../src/utils/filtering/boolean-logic-engine', () => ({
  testStringFilter: vi.fn(() => true),
  testNumericFilter: vi.fn(() => true),
  testBooleanFilter: vi.fn(() => true),
  testDateFilter: vi.fn(() => true),
}));

const CONTEXT = {} as any;
const USER = { id: 'user-1' } as any;

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

const seed = (...definitions: BasicStoreEntityCustomFieldDefinition[]) => {
  vi.spyOn(cacheModule, 'getEntitiesListFromCache').mockResolvedValue(definitions);
};

const unflatten = (stixExtensions: Record<string, any>) => unflattenStixToCustomFieldValues(CONTEXT, USER, stixExtensions);

describe('flattenCustomFieldValuesForStix', () => {
  it('returns an empty object when there are no custom field values', () => {
    expect(flattenCustomFieldValuesForStix(undefined)).toEqual({});
    expect(flattenCustomFieldValuesForStix([])).toEqual({});
  });

  it('flattens a string value', () => {
    const values: CustomFieldValue[] = [{ field_id: 'cf-1', field_name: 'x_opencti_cf_name', string_value: 'hello' }];
    expect(flattenCustomFieldValuesForStix(values)).toEqual({ x_opencti_cf_name: 'hello' });
  });

  it('flattens an integer value of zero without dropping it', () => {
    const values: CustomFieldValue[] = [{ field_id: 'cf-1', field_name: 'x_opencti_cf_score', int_value: 0 }];
    expect(flattenCustomFieldValuesForStix(values)).toEqual({ x_opencti_cf_score: 0 });
  });

  it('flattens a boolean value of false without dropping it', () => {
    const values: CustomFieldValue[] = [{ field_id: 'cf-1', field_name: 'x_opencti_cf_flag', boolean_value: false }];
    expect(flattenCustomFieldValuesForStix(values)).toEqual({ x_opencti_cf_flag: false });
  });

  it('flattens a select_values array (multi_select) using it over other channels', () => {
    const values: CustomFieldValue[] = [{ field_id: 'cf-1', field_name: 'x_opencti_cf_tags', select_values: ['a', 'b'] }];
    expect(flattenCustomFieldValuesForStix(values)).toEqual({ x_opencti_cf_tags: ['a', 'b'] });
  });

  it('flattens multiple custom fields at once', () => {
    const values: CustomFieldValue[] = [
      { field_id: 'cf-1', field_name: 'x_opencti_cf_score', int_value: 42 },
      { field_id: 'cf-2', field_name: 'x_opencti_cf_name', string_value: 'test' },
    ];
    expect(flattenCustomFieldValuesForStix(values)).toEqual({ x_opencti_cf_score: 42, x_opencti_cf_name: 'test' });
  });

  it('skips a custom field with no value set at all', () => {
    const values: CustomFieldValue[] = [{ field_id: 'cf-1', field_name: 'x_opencti_cf_empty' }];
    expect(flattenCustomFieldValuesForStix(values)).toEqual({});
  });
});

describe('unflattenStixToCustomFieldValues', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('returns undefined when the extension object is empty or nullish', async () => {
    seed();
    expect(await unflatten({})).toBeUndefined();
  });

  it('ignores keys not prefixed with the custom field prefix', async () => {
    seed();
    expect(await unflatten({ extension_type: 'new-sdo' })).toBeUndefined();
  });

  it('skips a custom field property with no matching cached definition (does not auto-create)', async () => {
    seed();
    expect(await unflatten({ x_opencti_cf_unknown: 'value' })).toBeUndefined();
  });

  it('converts a known integer custom field back to a CustomFieldValue', async () => {
    seed(makeDefinition({ id: 'cf-1', name: 'x_opencti_cf_score', field_type: 'integer' }));
    const result = await unflatten({ x_opencti_cf_score: 42 });
    expect(result).toEqual([{ field_id: 'cf-1', field_name: 'x_opencti_cf_score', int_value: 42 }]);
  });

  it('converts a known boolean custom field, coercing string "true"/"false" to a boolean', async () => {
    seed(makeDefinition({ id: 'cf-1', name: 'x_opencti_cf_flag', field_type: 'boolean' }));
    expect(await unflatten({ x_opencti_cf_flag: 'true' }))
      .toEqual([{ field_id: 'cf-1', field_name: 'x_opencti_cf_flag', boolean_value: true }]);
    expect(await unflatten({ x_opencti_cf_flag: false }))
      .toEqual([{ field_id: 'cf-1', field_name: 'x_opencti_cf_flag', boolean_value: false }]);
  });

  it('converts a known multi_select custom field array back to select_values of strings', async () => {
    seed(makeDefinition({ id: 'cf-1', name: 'x_opencti_cf_tags', field_type: 'multi_select' }));
    const result = await unflatten({ x_opencti_cf_tags: ['a', 'b'] });
    expect(result).toEqual([{ field_id: 'cf-1', field_name: 'x_opencti_cf_tags', select_values: ['a', 'b'] }]);
  });

  it('converts multiple known custom fields at once and ignores unknown ones', async () => {
    seed(
      makeDefinition({ id: 'cf-1', name: 'x_opencti_cf_score', field_type: 'integer' }),
      makeDefinition({ id: 'cf-2', name: 'x_opencti_cf_label', field_type: 'string' }),
    );
    const result = await unflatten({
      x_opencti_cf_score: 7,
      x_opencti_cf_label: 'test',
      x_opencti_cf_unknown: 'ignored',
      extension_type: 'new-sdo',
    });
    expect(result).toEqual(expect.arrayContaining([
      { field_id: 'cf-1', field_name: 'x_opencti_cf_score', int_value: 7 },
      { field_id: 'cf-2', field_name: 'x_opencti_cf_label', string_value: 'test' },
    ]));
    expect(result).toHaveLength(2);
  });

  it('round-trips flatten -> unflatten for a known definition', async () => {
    seed(makeDefinition({ id: 'cf-1', name: 'x_opencti_cf_score', field_type: 'integer' }));
    const original: CustomFieldValue[] = [{ field_id: 'cf-1', field_name: 'x_opencti_cf_score', int_value: 5 }];
    const flattened = flattenCustomFieldValuesForStix(original);
    const roundTripped = await unflatten(flattened);
    expect(roundTripped).toEqual(original);
  });
});

describe('getStixCustomFieldValue', () => {
  it('reads the value from the top-level data using the main custom field name', () => {
    const data = { x_opencti_cf_score: 42 };
    expect(getStixCustomFieldValue(data, 'x_opencti_cf_score', undefined)).toBe(42);
  });

  it('reads the value from one of the data extensions when not present at top-level', () => {
    const data = { extensions: { 'extension-definition--x': { x_opencti_cf_score: 7 } } };
    expect(getStixCustomFieldValue(data, 'x_opencti_cf_score', undefined)).toBe(7);
  });

  it('falls back to an alias at top-level when the main name is not present', () => {
    const data = { x_opencti_cf_old_name: 'legacy' };
    expect(getStixCustomFieldValue(data, 'x_opencti_cf_new_name', ['x_opencti_cf_old_name'])).toBe('legacy');
  });

  it('falls back to an alias inside an extension when neither the main name nor a top-level alias is present', () => {
    const data = { extensions: { 'extension-definition--x': { x_opencti_cf_old_name: 'legacy-ext' } } };
    expect(getStixCustomFieldValue(data, 'x_opencti_cf_new_name', ['x_opencti_cf_old_name'])).toBe('legacy-ext');
  });

  it('tries multiple aliases in order until one matches', () => {
    const data = { x_opencti_cf_second_alias: 'found' };
    expect(getStixCustomFieldValue(data, 'x_opencti_cf_name', ['x_opencti_cf_first_alias', 'x_opencti_cf_second_alias'])).toBe('found');
  });

  it('returns undefined when neither the main name nor any alias is found', () => {
    const data = { unrelated: 'value' };
    expect(getStixCustomFieldValue(data, 'x_opencti_cf_name', ['x_opencti_cf_alias'])).toBeUndefined();
  });

  it('returns undefined when there are no extensions and no aliases and the main name is absent', () => {
    const data = { unrelated: 'value' };
    expect(getStixCustomFieldValue(data, 'x_opencti_cf_name', null)).toBeUndefined();
  });

  it('prefers the main name over an alias when both are present', () => {
    const data = { x_opencti_cf_name: 'main-value', x_opencti_cf_alias: 'alias-value' };
    expect(getStixCustomFieldValue(data, 'x_opencti_cf_name', ['x_opencti_cf_alias'])).toBe('main-value');
  });
});

describe('buildCustomFieldStixFilterTester', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const filter = { key: ['x_opencti_cf_field'], values: ['a'], operator: FilterOperator.Eq } as any;

  it('dispatches to testStringFilter for string, select and multi_select field types', () => {
    for (const fieldType of ['string', 'select', 'multi_select'] as const) {
      const definition = makeDefinition({ name: 'x_opencti_cf_field', field_type: fieldType });
      const tester = buildCustomFieldStixFilterTester(definition);
      const stix = { x_opencti_cf_field: 'value' };
      const result = tester(stix, filter);
      expect(result).toBe(true);
      expect(BooleanLogicEngine.testStringFilter).toHaveBeenCalledWith(filter, 'value', undefined);
    }
  });

  it('dispatches to testNumericFilter for the integer field type', () => {
    const definition = makeDefinition({ name: 'x_opencti_cf_score', field_type: 'integer' });
    const tester = buildCustomFieldStixFilterTester(definition);
    const stix = { x_opencti_cf_score: 5 };
    tester(stix, filter);
    expect(BooleanLogicEngine.testNumericFilter).toHaveBeenCalledWith(filter, 5, undefined);
  });

  it('dispatches to testBooleanFilter for the boolean field type', () => {
    const definition = makeDefinition({ name: 'x_opencti_cf_flag', field_type: 'boolean' });
    const tester = buildCustomFieldStixFilterTester(definition);
    const stix = { x_opencti_cf_flag: true };
    tester(stix, filter);
    expect(BooleanLogicEngine.testBooleanFilter).toHaveBeenCalledWith(filter, true, undefined);
  });

  it('dispatches to testDateFilter for the date field type', () => {
    const definition = makeDefinition({ name: 'x_opencti_cf_date', field_type: 'date' });
    const tester = buildCustomFieldStixFilterTester(definition);
    const stix = { x_opencti_cf_date: '2026-01-01' };
    tester(stix, filter);
    expect(BooleanLogicEngine.testDateFilter).toHaveBeenCalledWith(filter, '2026-01-01');
  });

  it('forwards aliases and changeContext when resolving the stix value', () => {
    const definition = makeDefinition({ name: 'x_opencti_cf_field', field_type: 'string', aliases: ['x_opencti_cf_legacy'] } as any);
    const tester = buildCustomFieldStixFilterTester(definition);
    const stix = { x_opencti_cf_legacy: 'legacy-value' };
    const changeContext = { filterKey: 'x_opencti_cf_field', eventContext: { isCreation: true, changedAttributes: [] } } as any;
    tester(stix, filter, changeContext);
    expect(BooleanLogicEngine.testStringFilter).toHaveBeenCalledWith(filter, 'legacy-value', changeContext);
  });

  it('throws for an unsupported field type', () => {
    const definition = makeDefinition({ name: 'x_opencti_cf_field', field_type: 'unsupported' as any });
    const tester = buildCustomFieldStixFilterTester(definition);
    expect(() => tester({ x_opencti_cf_field: 'value' }, filter)).toThrow('Unsupported custom field type');
  });
});

describe('getCustomFieldsStixFilterTesters', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('returns an empty map when there are no custom field definitions', async () => {
    seed();
    const testers = await getCustomFieldsStixFilterTesters(CONTEXT, USER);
    expect(testers).toEqual({});
  });

  it('builds a map keyed by field name with a working tester function for each definition', async () => {
    seed(
      makeDefinition({ name: 'x_opencti_cf_score', field_type: 'integer' }),
      makeDefinition({ name: 'x_opencti_cf_label', field_type: 'string' }),
    );
    const testers = await getCustomFieldsStixFilterTesters(CONTEXT, USER);
    expect(Object.keys(testers).sort()).toEqual(['x_opencti_cf_label', 'x_opencti_cf_score']);
    expect(typeof testers.x_opencti_cf_score).toBe('function');
    expect(typeof testers.x_opencti_cf_label).toBe('function');
  });
});
