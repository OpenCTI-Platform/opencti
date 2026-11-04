import { describe, it, expect } from 'vitest';
import { isResolvableId, parseUpdatesPatch, buildFieldLabelMap, formatFieldKey } from './draftReviewDiffPanelUtils';

describe('isResolvableId', () => {
  it('should return true for a valid STIX ID', () => {
    expect(isResolvableId('malware--12345678-1234-1234-1234-123456789012')).toBe(true);
  });

  it('should return true for a valid UUID', () => {
    expect(isResolvableId('12345678-1234-1234-1234-123456789012')).toBe(true);
  });

  it('should return false for a plain string', () => {
    expect(isResolvableId('some-plain-value')).toBe(false);
  });

  it('should return false for an empty string', () => {
    expect(isResolvableId('')).toBe(false);
  });
});

describe('parseUpdatesPatch', () => {
  it('should return empty array for null', () => {
    expect(parseUpdatesPatch(null)).toEqual([]);
  });

  it('should return empty array for undefined', () => {
    expect(parseUpdatesPatch(undefined)).toEqual([]);
  });

  it('should return empty array for empty string', () => {
    expect(parseUpdatesPatch('')).toEqual([]);
  });

  it('should return empty array for invalid JSON', () => {
    expect(parseUpdatesPatch('not-json')).toEqual([]);
  });

  it('should filter out EXCLUDED_PATCH_FIELDS (standard_id, objects)', () => {
    const patch = JSON.stringify({
      standard_id: { initial_value: ['old-id'], replaced_value: ['new-id'], added_value: [], removed_value: [] },
      objects: { initial_value: [], replaced_value: [], added_value: ['obj1'], removed_value: [] },
      name: { initial_value: ['Old Name'], replaced_value: ['New Name'], added_value: [], removed_value: [] },
    });
    const result = parseUpdatesPatch(patch);
    expect(result).toHaveLength(1);
    expect(result[0].field).toBe('name');
  });

  it('should use replaced_value when present and non-empty', () => {
    const patch = JSON.stringify({
      name: {
        initial_value: ['Old Name'],
        replaced_value: ['New Name'],
        added_value: [],
        removed_value: [],
      },
    });
    const result = parseUpdatesPatch(patch);
    expect(result).toHaveLength(1);
    expect(result[0]).toEqual({
      field: 'name',
      removed: ['Old Name'],
      added: ['New Name'],
    });
  });

  it('should use added_value and removed_value when replaced_value is empty', () => {
    const patch = JSON.stringify({
      labels: {
        initial_value: ['tag1', 'tag2'],
        replaced_value: [],
        added_value: ['tag3'],
        removed_value: ['tag2'],
      },
    });
    const result = parseUpdatesPatch(patch);
    expect(result).toHaveLength(1);
    expect(result[0]).toEqual({
      field: 'labels',
      removed: ['tag1', 'tag2'],
      added: ['tag1', 'tag3'],
    });
  });

  it('should handle multiple fields', () => {
    const patch = JSON.stringify({
      name: { initial_value: ['A'], replaced_value: ['B'], added_value: [], removed_value: [] },
      description: { initial_value: ['X'], replaced_value: ['Y'], added_value: [], removed_value: [] },
    });
    const result = parseUpdatesPatch(patch);
    expect(result).toHaveLength(2);
  });

  it('should build one change per custom field actually modified', () => {
    const note = (value: string) => ({ field_id: 'cf-note', field_name: 'x_opencti_cf_note', string_value: value });
    const score = { field_id: 'cf-score', field_name: 'x_opencti_cf_score', int_value: 10 };
    const tags = { field_id: 'cf-tags', field_name: 'x_opencti_cf_tags', select_values: ['a', 'b'] };
    const patch = JSON.stringify({
      custom_field_values: {
        initial_value: [note('before'), score],
        replaced_value: [score, note('after'), tags],
        added_value: [],
        removed_value: [],
      },
    });
    expect(parseUpdatesPatch(patch)).toEqual([
      { field: 'x_opencti_cf_note', removed: ['before'], added: ['after'] },
      { field: 'x_opencti_cf_tags', removed: [], added: ['a, b'] },
    ]);
  });

  it('should apply added and removed custom field values', () => {
    const patch = JSON.stringify({
      custom_field_values: {
        initial_value: [{ field_id: 'cf-note', field_name: 'x_opencti_cf_note', string_value: 'before' }],
        replaced_value: [],
        added_value: [{ field_id: 'cf-flag', field_name: 'x_opencti_cf_flag', boolean_value: false }],
        removed_value: [{ field_id: 'cf-note', field_name: 'x_opencti_cf_note' }],
      },
    });
    expect(parseUpdatesPatch(patch)).toEqual([
      { field: 'x_opencti_cf_note', removed: ['before'], added: [] },
      { field: 'x_opencti_cf_flag', removed: [], added: ['false'] },
    ]);
  });

  it('should show every custom field cleared by a replacement with an empty list', () => {
    const note = { field_id: 'cf-note', field_name: 'x_opencti_cf_note', string_value: 'before' };
    const score = { field_id: 'cf-score', field_name: 'x_opencti_cf_score', int_value: 10 };
    const patch = JSON.stringify({
      custom_field_values: { initial_value: [note, score], replaced_value: [], added_value: [], removed_value: [] },
    });
    // The draft version has no custom field value left
    expect(parseUpdatesPatch(patch, [])).toEqual([
      { field: 'x_opencti_cf_note', removed: ['before'], added: [] },
      { field: 'x_opencti_cf_score', removed: ['10'], added: [] },
    ]);
  });

  it('should show a multi_select change whose displayed values look alike', () => {
    const tags = (selectValues: string[]) => ({ field_id: 'cf-tags', field_name: 'x_opencti_cf_tags', select_values: selectValues });
    const patch = JSON.stringify({
      custom_field_values: { initial_value: [tags(['a, b'])], replaced_value: [tags(['a', 'b'])], added_value: [], removed_value: [] },
    });
    expect(parseUpdatesPatch(patch)).toEqual([{ field: 'x_opencti_cf_tags', removed: ['a, b'], added: ['a, b'] }]);
  });

  it('should compare the initial custom field values with the ones of the draft version', () => {
    const patch = JSON.stringify({
      custom_field_values: {
        initial_value: [{ field_id: 'cf-note', field_name: 'x_opencti_cf_note', string_value: 'before' }],
        replaced_value: [],
        added_value: [{ field_id: 'cf-note', field_name: 'x_opencti_cf_note', string_value: 'intermediate' }],
        removed_value: [],
      },
    });
    const draftValues = [{ field_id: 'cf-note', field_name: 'x_opencti_cf_note', string_value: 'after' }];
    expect(parseUpdatesPatch(patch, draftValues)).toEqual([{ field: 'x_opencti_cf_note', removed: ['before'], added: ['after'] }]);
  });
});

describe('buildFieldLabelMap', () => {
  it('should return empty object for null', () => {
    expect(buildFieldLabelMap(null)).toEqual({});
  });

  it('should return empty object for undefined', () => {
    expect(buildFieldLabelMap(undefined)).toEqual({});
  });

  it('should map attribute names to their labels', () => {
    const attrs = [
      { name: 'confidence', label: 'Confidence' },
      { name: 'description', label: 'Description' },
    ];
    expect(buildFieldLabelMap(attrs)).toEqual({
      confidence: 'Confidence',
      description: 'Description',
    });
  });

  it('should ignore attributes without a label', () => {
    const attrs = [
      { name: 'confidence', label: 'Confidence' },
      { name: 'internal_field', label: null },
      { name: 'other_field', label: undefined },
    ];
    const result = buildFieldLabelMap(attrs);
    expect(Object.keys(result)).toEqual(['confidence']);
  });
});

describe('formatFieldKey', () => {
  it('should return empty string for undefined field', () => {
    expect(formatFieldKey(undefined, {})).toBe('');
  });

  it('should use i18n translation when it differs from the key', () => {
    const t_i18n = (key: string) => (key === 'confidence' ? 'Confidence level' : key);
    expect(formatFieldKey('confidence', {}, t_i18n)).toBe('Confidence level');
  });

  it('should fall back to labelMap when i18n returns the key unchanged', () => {
    const t_i18n = (key: string) => key;
    const labelMap = { confidence: 'Confidence (from schema)' };
    expect(formatFieldKey('confidence', labelMap, t_i18n)).toBe('Confidence (from schema)');
  });

  it('should fall back to formatted field name when no i18n or labelMap match', () => {
    expect(formatFieldKey('x_opencti_score', {})).toBe('Score');
  });

  it('should replace underscores and capitalize for plain field names', () => {
    expect(formatFieldKey('first_seen', {})).toBe('First seen');
  });

  it('should use labelMap when no t_i18n is provided', () => {
    const labelMap = { confidence: 'Confidence' };
    expect(formatFieldKey('confidence', labelMap)).toBe('Confidence');
  });
});
