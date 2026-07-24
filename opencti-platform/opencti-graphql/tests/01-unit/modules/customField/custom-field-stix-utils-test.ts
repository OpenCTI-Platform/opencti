import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as cacheModule from '../../../../src/database/cache';
import { flattenCustomFieldValuesForStix, unflattenStixToCustomFieldValues } from '../../../../src/modules/customField/custom-field-stix-utils';
import type { BasicStoreEntityCustomFieldDefinition, CustomFieldValue } from '../../../../src/modules/customField/custom-field-types';

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
