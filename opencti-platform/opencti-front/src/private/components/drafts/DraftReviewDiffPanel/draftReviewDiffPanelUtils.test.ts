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
