import { describe, expect, it } from 'vitest';
import { isAttributeMultiple, isPlaybookUpdateActionValid, toCustomFieldActionValue } from './playbookAction-types';
import type { CustomFieldDefinition } from '../../../../../common/custom_fields/useCustomFieldDefinitions';

const definitions = [
  { id: 'cf-1', name: 'x_opencti_cf_sectors', label: 'Sectors', field_type: 'multi_select', entity_types: ['Malware'] },
  { id: 'cf-2', name: 'x_opencti_cf_owner', label: 'Owner', field_type: 'string', entity_types: ['Malware'] },
] as unknown as CustomFieldDefinition[];

describe('playbook update actions with custom fields', () => {
  it('detects a multiple attribute, multi_select custom fields included', () => {
    expect(isAttributeMultiple('objectLabel', definitions)).toBe(true);
    expect(isAttributeMultiple('x_opencti_score', definitions)).toBe(false);
    expect(isAttributeMultiple('x_opencti_cf_sectors', definitions)).toBe(true);
    expect(isAttributeMultiple('x_opencti_cf_owner', definitions)).toBe(false);
  });

  it('converts a custom field value to action values', () => {
    expect(toCustomFieldActionValue(['a', 'b'])).toEqual([
      { label: 'a', value: 'a', patch_value: 'a' },
      { label: 'b', value: 'b', patch_value: 'b' },
    ]);
    expect(toCustomFieldActionValue(false)).toEqual([{ label: 'false', value: 'false', patch_value: 'false' }]);
    expect(toCustomFieldActionValue('42')).toEqual([{ label: '42', value: '42', patch_value: '42' }]);
    expect(toCustomFieldActionValue('')).toEqual([]);
  });

  it('accepts removing a custom field without value', () => {
    expect(isPlaybookUpdateActionValid({ op: 'remove', attribute: 'x_opencti_cf_owner', value: [] })).toBe(true);
    expect(isPlaybookUpdateActionValid({ op: 'replace', attribute: 'x_opencti_cf_owner', value: [] })).toBe(false);
    expect(isPlaybookUpdateActionValid({ op: 'remove', attribute: 'objectLabel', value: [] })).toBe(false);
    expect(isPlaybookUpdateActionValid({ op: 'replace', attribute: 'x_opencti_detection' })).toBe(true);
  });
});
