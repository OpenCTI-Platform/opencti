import { describe, expect, it } from 'vitest';
import { buildCustomFieldPlaybookOperations, computeCustomFieldActionValue, type CustomFieldPlaybookAction } from '../../../../src/modules/customField/custom-field-playbook';
import type { BasicStoreEntityCustomFieldDefinition } from '../../../../src/modules/customField/custom-field-types';
import type { StixObject } from '../../../../src/types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../../../src/types/stix-2-1-extensions';

const makeDefinition = (overrides: Partial<BasicStoreEntityCustomFieldDefinition> = {}): BasicStoreEntityCustomFieldDefinition => ({
  id: 'cf-id-1',
  name: 'x_opencti_cf_field',
  label: 'Field',
  field_type: 'string',
  entity_types: ['Malware'],
  entity_type_settings: [],
  ...overrides,
} as unknown as BasicStoreEntityCustomFieldDefinition);

const INTEGER = makeDefinition({ id: 'cf-int', name: 'x_opencti_cf_score', field_type: 'integer' });
const BOOLEAN = makeDefinition({ id: 'cf-bool', name: 'x_opencti_cf_flag', field_type: 'boolean' });
const MULTI = makeDefinition({ id: 'cf-multi', name: 'x_opencti_cf_sectors', field_type: 'multi_select' });
const STRING = makeDefinition({ id: 'cf-string', name: 'x_opencti_cf_owner', field_type: 'string' });

const action = (op: CustomFieldPlaybookAction['op'], attribute: string, values: string[]): CustomFieldPlaybookAction => ({
  op,
  attribute,
  value: values.map((v) => ({ patch_value: v })),
});

const element = (extension: Record<string, any> = {}, topLevel: Record<string, any> = {}) => ({
  id: 'malware--1',
  type: 'malware',
  ...topLevel,
  extensions: { [STIX_EXT_OCTI]: { id: 'internal-id', type: 'Malware', ...extension } },
} as unknown as StixObject);

describe('computeCustomFieldActionValue', () => {
  it('converts the value to the field type', () => {
    expect(computeCustomFieldActionValue(INTEGER, action('replace', INTEGER.name, ['42']), 1)).toBe(42);
    expect(computeCustomFieldActionValue(BOOLEAN, action('replace', BOOLEAN.name, ['false']), true)).toBe(false);
    expect(computeCustomFieldActionValue(STRING, action('add', STRING.name, ['bob']), undefined)).toBe('bob');
  });

  it('clears a single value field on remove', () => {
    expect(computeCustomFieldActionValue(STRING, action('remove', STRING.name, []), 'bob')).toBeUndefined();
  });

  it('adds, replaces and removes multi_select options', () => {
    expect(computeCustomFieldActionValue(MULTI, action('add', MULTI.name, ['b', 'c']), ['a', 'b'])).toEqual(['a', 'b', 'c']);
    expect(computeCustomFieldActionValue(MULTI, action('replace', MULTI.name, ['c']), ['a', 'b'])).toEqual(['c']);
    expect(computeCustomFieldActionValue(MULTI, action('remove', MULTI.name, ['b']), ['a', 'b'])).toEqual(['a']);
    expect(computeCustomFieldActionValue(MULTI, action('remove', MULTI.name, []), ['a', 'b'])).toEqual([]);
  });
});

describe('buildCustomFieldPlaybookOperations', () => {
  const definitions = [INTEGER, BOOLEAN, MULTI, STRING];

  it('sets the value in the OpenCTI extension and replaces the field on upsert', () => {
    const result = buildCustomFieldPlaybookOperations(element({ x_opencti_cf_score: 1 }), '/objects/0', [action('replace', INTEGER.name, ['42'])], definitions);
    expect(result.patchOperations).toEqual([{ op: 'add', path: `/objects/0/extensions/${STIX_EXT_OCTI}/x_opencti_cf_score`, value: 42 }]);
    expect(result.upsertOperations).toEqual([{
      key: 'custom_field_values',
      operation: 'replace',
      value: [{ field_id: 'cf-int', field_name: 'x_opencti_cf_score', int_value: 42 }],
    }]);
  });

  it('keeps a boolean false value', () => {
    const result = buildCustomFieldPlaybookOperations(element({ x_opencti_cf_flag: true }), '/objects/0', [action('replace', BOOLEAN.name, ['false'])], definitions);
    expect(result.patchOperations).toEqual([{ op: 'add', path: `/objects/0/extensions/${STIX_EXT_OCTI}/x_opencti_cf_flag`, value: false }]);
    expect(result.upsertOperations[0].value).toEqual([{ field_id: 'cf-bool', field_name: 'x_opencti_cf_flag', boolean_value: false }]);
  });

  it('writes a top level custom property where it is', () => {
    const result = buildCustomFieldPlaybookOperations(element({}, { x_opencti_cf_owner: 'alice' }), '/objects/2', [action('replace', STRING.name, ['bob'])], definitions);
    expect(result.patchOperations).toEqual([{ op: 'add', path: '/objects/2/x_opencti_cf_owner', value: 'bob' }]);
  });

  it('removes the property and the field on clear', () => {
    const result = buildCustomFieldPlaybookOperations(
      element({ x_opencti_cf_owner: 'alice' }, { x_opencti_cf_owner: 'alice' }),
      '/objects/0',
      [action('remove', STRING.name, [])],
      definitions,
    );
    expect(result.patchOperations).toEqual([
      { op: 'remove', path: '/objects/0/x_opencti_cf_owner' },
      { op: 'remove', path: `/objects/0/extensions/${STIX_EXT_OCTI}/x_opencti_cf_owner` },
    ]);
    expect(result.upsertOperations).toEqual([{ key: 'custom_field_values', operation: 'remove', value: [{ field_id: 'cf-string', field_name: 'x_opencti_cf_owner' }] }]);
  });

  it('clears a field the element does not carry only on upsert', () => {
    const result = buildCustomFieldPlaybookOperations(element(), '/objects/0', [action('remove', STRING.name, [])], definitions);
    expect(result.patchOperations).toEqual([]);
    expect(result.upsertOperations).toEqual([{ key: 'custom_field_values', operation: 'remove', value: [{ field_id: 'cf-string', field_name: 'x_opencti_cf_owner' }] }]);
  });

  it('applies successive actions on the same field', () => {
    const result = buildCustomFieldPlaybookOperations(
      element({ x_opencti_cf_sectors: ['a', 'b'] }),
      '/objects/0',
      [action('remove', MULTI.name, ['a']), action('add', MULTI.name, ['c'])],
      definitions,
    );
    expect(result.patchOperations).toEqual([{ op: 'add', path: `/objects/0/extensions/${STIX_EXT_OCTI}/x_opencti_cf_sectors`, value: ['b', 'c'] }]);
    // The stored value is changed incrementally, not replaced by the one computed from the bundle snapshot
    expect(result.upsertOperations).toEqual([
      { key: 'custom_field_values', operation: 'remove', value: [{ field_id: 'cf-multi', field_name: 'x_opencti_cf_sectors', select_values: ['a'] }] },
      { key: 'custom_field_values', operation: 'add', value: [{ field_id: 'cf-multi', field_name: 'x_opencti_cf_sectors', select_values: ['c'] }] },
    ]);
  });

  it('ignores a field not attached to the element type and a mistyped value', () => {
    const result = buildCustomFieldPlaybookOperations(
      element(),
      '/objects/0',
      [action('replace', 'x_opencti_cf_unknown', ['x']), action('replace', INTEGER.name, ['not a number'])],
      definitions,
    );
    expect(result).toEqual({ patchOperations: [], upsertOperations: [] });
  });

  it('replaces the options of a multi_select and clears it when removing without option', () => {
    const replaced = buildCustomFieldPlaybookOperations(element({ x_opencti_cf_sectors: ['a'] }), '/objects/0', [action('replace', MULTI.name, ['c', 'c'])], definitions);
    expect(replaced.upsertOperations).toEqual([
      { key: 'custom_field_values', operation: 'replace', value: [{ field_id: 'cf-multi', field_name: 'x_opencti_cf_sectors', select_values: ['c'] }] },
    ]);
    const cleared = buildCustomFieldPlaybookOperations(element({ x_opencti_cf_sectors: ['a'] }), '/objects/0', [action('remove', MULTI.name, [])], definitions);
    expect(cleared.upsertOperations).toEqual([{ key: 'custom_field_values', operation: 'remove', value: [{ field_id: 'cf-multi', field_name: 'x_opencti_cf_sectors' }] }]);
  });
});
