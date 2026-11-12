import { describe, expect, it } from 'vitest';
import { mergeUpsertInputs } from '../../../src/utils/upsert-utils';

const SCORE = { field_id: 'cf-int', field_name: 'x_opencti_cf_score', int_value: 1 };
const OWNER = { field_id: 'cf-string', field_name: 'x_opencti_cf_owner', string_value: 'alice' };
const SECTORS = { field_id: 'cf-multi', field_name: 'x_opencti_cf_sectors', select_values: ['a', 'b'] };

const element = { custom_field_values: [SCORE, OWNER, SECTORS] };
const bundleInput = (value: any[]) => ({ key: 'custom_field_values', operation: 'add', value });

describe('mergeUpsertInputs with custom field values', () => {
  it('replaces only the field of the upsert operation', () => {
    const inputs = mergeUpsertInputs(element, {}, [bundleInput([SCORE, OWNER, { ...SECTORS, select_values: ['c'] }])], [
      { key: 'custom_field_values', operation: 'replace', value: [{ ...SECTORS, select_values: ['c'] }] },
    ]);
    expect(inputs).toEqual([{ key: 'custom_field_values', operation: 'replace', value: [SCORE, OWNER, { ...SECTORS, select_values: ['c'] }] }]);
  });

  it('removes only the field of the upsert operation', () => {
    const inputs = mergeUpsertInputs(element, {}, [bundleInput([SCORE, SECTORS])], [
      { key: 'custom_field_values', operation: 'remove', value: [{ field_id: 'cf-string' }] },
    ]);
    expect(inputs).toEqual([{ key: 'custom_field_values', operation: 'replace', value: [SCORE, SECTORS] }]);
  });

  it('keeps the other fields without bundle values', () => {
    const inputs = mergeUpsertInputs(element, {}, [], [
      { key: 'custom_field_values', operation: 'remove', value: [{ field_id: 'cf-int' }] },
      { key: 'custom_field_values', operation: 'replace', value: [{ ...OWNER, string_value: 'bob' }] },
    ]);
    expect(inputs).toEqual([{ key: 'custom_field_values', operation: 'replace', value: [{ ...OWNER, string_value: 'bob' }, SECTORS] }]);
  });

  it('upserts the bundle values of the other fields as usual', () => {
    const inputs = mergeUpsertInputs(element, {}, [bundleInput([{ ...SCORE, int_value: 5 }, { ...SECTORS, select_values: ['c'] }])], [
      { key: 'custom_field_values', operation: 'remove', value: [{ field_id: 'cf-string' }] },
    ]);
    expect(inputs).toEqual([{ key: 'custom_field_values', operation: 'replace', value: [{ ...SCORE, int_value: 5 }, { ...SECTORS, select_values: ['a', 'b', 'c'] }] }]);
  });

  it('unites multi_select options on add', () => {
    const inputs = mergeUpsertInputs(element, {}, [], [
      { key: 'custom_field_values', operation: 'add', value: [{ ...SECTORS, select_values: ['c'] }] },
    ]);
    expect(inputs).toEqual([{ key: 'custom_field_values', operation: 'replace', value: [SCORE, OWNER, { ...SECTORS, select_values: ['a', 'b', 'c'] }] }]);
  });

  it('adds a field the element does not carry yet', () => {
    const inputs = mergeUpsertInputs({}, {}, [], [{ key: 'custom_field_values', operation: 'replace', value: [OWNER] }]);
    expect(inputs).toEqual([{ key: 'custom_field_values', operation: 'replace', value: [OWNER] }]);
  });

  it('removes only the given options of a multi_select', () => {
    const inputs = mergeUpsertInputs(element, {}, [], [
      { key: 'custom_field_values', operation: 'remove', value: [{ field_id: 'cf-multi', select_values: ['a'] }] },
    ]);
    expect(inputs).toEqual([{ key: 'custom_field_values', operation: 'replace', value: [SCORE, OWNER, { ...SECTORS, select_values: ['b'] }] }]);
    const allRemoved = mergeUpsertInputs(element, {}, [], [
      { key: 'custom_field_values', operation: 'remove', value: [{ field_id: 'cf-multi', select_values: ['a', 'b'] }] },
    ]);
    expect(allRemoved).toEqual([{ key: 'custom_field_values', operation: 'replace', value: [SCORE, OWNER] }]);
  });

  it('applies the options added and removed by successive operations on the stored value', () => {
    const inputs = mergeUpsertInputs(element, {}, [bundleInput([{ ...SECTORS, select_values: ['z'] }])], [
      { key: 'custom_field_values', operation: 'add', value: [{ field_id: 'cf-multi', field_name: 'x_opencti_cf_sectors', select_values: ['c'] }] },
      { key: 'custom_field_values', operation: 'remove', value: [{ field_id: 'cf-multi', field_name: 'x_opencti_cf_sectors', select_values: ['a'] }] },
    ]);
    // The stale bundle value of the operated field is ignored
    expect(inputs).toEqual([{ key: 'custom_field_values', operation: 'replace', value: [SCORE, OWNER, { ...SECTORS, select_values: ['b', 'c'] }] }]);
  });
});
