import { describe, expect, it } from 'vitest';
import { buildCustomFieldsTelemetryItems, isDashboardManifestUsingCustomField, isFilterGroupUsingCustomField } from '../../../../src/modules/customField/custom-field-telemetry';
import type { BasicStoreEntityCustomFieldDefinition } from '../../../../src/modules/customField/custom-field-types';
import { toB64 } from '../../../../src/utils/base64';

const filterGroup = (key: string, nestedKey?: string) => ({
  mode: 'and',
  filters: [{ key: [key], values: ['a'] }],
  filterGroups: nestedKey ? [{ mode: 'and', filters: [{ key: [nestedKey], values: ['b'] }], filterGroups: [] }] : [],
});

describe('isFilterGroupUsingCustomField', () => {
  it('detects a custom field key, including in nested groups and JSON strings', () => {
    expect(isFilterGroupUsingCustomField(filterGroup('x_opencti_cf_priority'))).toBe(true);
    expect(isFilterGroupUsingCustomField(filterGroup('entity_type', 'x_opencti_cf_priority'))).toBe(true);
    expect(isFilterGroupUsingCustomField(JSON.stringify(filterGroup('x_opencti_cf_priority')))).toBe(true);
  });

  it('returns false without custom field key or on empty and malformed filters', () => {
    expect(isFilterGroupUsingCustomField(filterGroup('entity_type'))).toBe(false);
    expect(isFilterGroupUsingCustomField(undefined)).toBe(false);
    expect(isFilterGroupUsingCustomField('')).toBe(false);
    expect(isFilterGroupUsingCustomField('{not json')).toBe(false);
  });
});

describe('isDashboardManifestUsingCustomField', () => {
  const manifest = (selection: Record<string, unknown>) => toB64({ widgets: { w1: { dataSelection: [selection] } } });

  it('detects a custom field in widget filters, dynamicFrom or dynamicTo', () => {
    expect(isDashboardManifestUsingCustomField(manifest({ filters: filterGroup('x_opencti_cf_priority') }))).toBe(true);
    expect(isDashboardManifestUsingCustomField(manifest({ dynamicFrom: filterGroup('x_opencti_cf_priority') }))).toBe(true);
    expect(isDashboardManifestUsingCustomField(manifest({ dynamicTo: filterGroup('x_opencti_cf_priority') }))).toBe(true);
  });

  it('returns false without custom field filter, without widgets or on an empty manifest', () => {
    expect(isDashboardManifestUsingCustomField(manifest({ filters: filterGroup('entity_type') }))).toBe(false);
    expect(isDashboardManifestUsingCustomField(toB64({}))).toBe(false);
    expect(isDashboardManifestUsingCustomField(undefined)).toBe(false);
  });
});

describe('buildCustomFieldsTelemetryItems', () => {
  const definition = (field_type: string, entity_types: string[]) => ({ field_type, entity_types } as unknown as BasicStoreEntityCustomFieldDefinition);

  it('counts definitions per attached entity type and per field type', () => {
    const { byEntityType, byFieldType } = buildCustomFieldsTelemetryItems([
      definition('integer', ['Report', 'Case-Incident']),
      definition('select', ['Report']),
    ]);
    expect(byEntityType).toEqual(expect.arrayContaining([
      { value: 2, attributes: { entity_type: 'Report' } },
      { value: 1, attributes: { entity_type: 'Case-Incident' } },
    ]));
    expect(byEntityType).toHaveLength(2);
    expect(byFieldType).toHaveLength(7);
    expect(byFieldType).toEqual(expect.arrayContaining([
      { value: 1, attributes: { field_type: 'integer' } },
      { value: 1, attributes: { field_type: 'select' } },
      { value: 0, attributes: { field_type: 'date' } },
    ]));
  });
});
