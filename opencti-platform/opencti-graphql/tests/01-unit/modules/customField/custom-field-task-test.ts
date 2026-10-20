import { describe, expect, it } from 'vitest';
import { buildCustomFieldTaskInputs } from '../../../../src/modules/customField/custom-field-task';
import type { BasicStoreEntityCustomFieldDefinition } from '../../../../src/modules/customField/custom-field-types';

const makeDefinition = (name: string, field_type: string) => ({ id: `${name}-id`, name, field_type, entity_types: ['Malware'] } as unknown as BasicStoreEntityCustomFieldDefinition);

const INTEGER = makeDefinition('x_opencti_cf_score', 'integer');
const BOOLEAN = makeDefinition('x_opencti_cf_flag', 'boolean');
const DATE = makeDefinition('x_opencti_cf_due', 'date');
const MULTI = makeDefinition('x_opencti_cf_sectors', 'multi_select');

describe('buildCustomFieldTaskInputs', () => {
  it('sets a single value field with its typed value', () => {
    expect(buildCustomFieldTaskInputs(INTEGER, 'REPLACE', ['42'])).toEqual([
      { key: 'custom_field_values', operation: 'add', value: [{ field_name: 'x_opencti_cf_score', int_value: 42 }] },
    ]);
    expect(buildCustomFieldTaskInputs(BOOLEAN, 'REPLACE', ['false'])).toEqual([
      { key: 'custom_field_values', operation: 'add', value: [{ field_name: 'x_opencti_cf_flag', boolean_value: false }] },
    ]);
    expect(buildCustomFieldTaskInputs(DATE, 'ADD', ['2026-10-14T00:00:00.000Z'])).toEqual([
      { key: 'custom_field_values', operation: 'add', value: [{ field_name: 'x_opencti_cf_due', date_value: '2026-10-14T00:00:00.000Z' }] },
    ]);
  });

  it('clears a field on remove, or on replace without value', () => {
    const clear = [{ key: 'custom_field_values', operation: 'remove', value: [{ field_name: 'x_opencti_cf_score' }] }];
    expect(buildCustomFieldTaskInputs(INTEGER, 'REMOVE', [])).toEqual(clear);
    expect(buildCustomFieldTaskInputs(INTEGER, 'REMOVE', ['42'])).toEqual(clear);
    expect(buildCustomFieldTaskInputs(INTEGER, 'REPLACE', [])).toEqual(clear);
    expect(buildCustomFieldTaskInputs(INTEGER, 'ADD', [])).toEqual([]);
  });

  it('adds, replaces and removes multi_select options', () => {
    expect(buildCustomFieldTaskInputs(MULTI, 'ADD', ['a', 'b'])).toEqual([
      { key: 'custom_field_values', operation: 'add', value: [{ field_name: 'x_opencti_cf_sectors', select_values: ['a', 'b'] }] },
    ]);
    expect(buildCustomFieldTaskInputs(MULTI, 'REPLACE', ['c'])).toEqual([
      { key: 'custom_field_values', operation: 'remove', value: [{ field_name: 'x_opencti_cf_sectors' }] },
      { key: 'custom_field_values', operation: 'add', value: [{ field_name: 'x_opencti_cf_sectors', select_values: ['c'] }] },
    ]);
    expect(buildCustomFieldTaskInputs(MULTI, 'REMOVE', ['a'])).toEqual([
      { key: 'custom_field_values', operation: 'remove', value: [{ field_name: 'x_opencti_cf_sectors', select_values: ['a'] }] },
    ]);
  });
});
