import { describe, expect, it } from 'vitest';
import convertRetentionRuleToStix from '../../../../src/modules/retentionRules/retentionRules-converter';
import { ENTITY_TYPE_RETENTION_RULE, type StoreEntityRetentionRule } from '../../../../src/modules/retentionRules/retentionRules-types';
import { STIX_EXT_OCTI } from '../../../../src/types/stix-2-1-extensions';

describe('retentionRules converter - convertRetentionRuleToStix', () => {
  const buildMockRetentionRule = (overrides: Partial<StoreEntityRetentionRule> = {}): StoreEntityRetentionRule => {
    return {
      internal_id: 'retention-rule-internal-id-1',
      standard_id: 'retention-rule--00000000-0000-0000-0000-000000000001',
      entity_type: ENTITY_TYPE_RETENTION_RULE,
      name: 'Test Retention Rule',
      filters: JSON.stringify({ mode: 'and', filters: [], filterGroups: [] }),
      max_retention: 30,
      retention_unit: 'days',
      scope: 'knowledge',
      last_execution_date: '2026-04-01T00:00:00.000Z',
      last_deleted_count: 5,
      remaining_count: 42,
      ...overrides,
    } as unknown as StoreEntityRetentionRule;
  };

  it('should convert all module-specific properties to STIX format', () => {
    const instance = buildMockRetentionRule();
    const stix = convertRetentionRuleToStix(instance);

    expect(stix.name).toBe('Test Retention Rule');
    expect(stix.filters).toBe(JSON.stringify({ mode: 'and', filters: [], filterGroups: [] }));
    expect(stix.max_retention).toBe(30);
    expect(stix.retention_unit).toBe('days');
    expect(stix.scope).toBe('knowledge');
    expect(stix.last_execution_date).toBe('2026-04-01T00:00:00.000Z');
    expect(stix.last_deleted_count).toBe(5);
    expect(stix.remaining_count).toBe(42);
  });

  it('should set extension_type to new-sdo', () => {
    const instance = buildMockRetentionRule();
    const stix = convertRetentionRuleToStix(instance);

    expect(stix.extensions[STIX_EXT_OCTI].extension_type).toBe('new-sdo');
  });

  it('should include base STIX fields from buildStixObject', () => {
    const instance = buildMockRetentionRule();
    const stix = convertRetentionRuleToStix(instance);

    expect(stix.id).toBeDefined();
    expect(stix.spec_version).toBe('2.1');
    expect(stix.extensions).toBeDefined();
    expect(stix.extensions[STIX_EXT_OCTI]).toBeDefined();
  });

  it('should handle null values for optional fields', () => {
    const instance = buildMockRetentionRule({
      last_execution_date: null,
      last_deleted_count: null,
      remaining_count: null,
    });
    const stix = convertRetentionRuleToStix(instance);

    expect(stix.name).toBe('Test Retention Rule');
    expect(stix.max_retention).toBe(30);
    expect(stix.scope).toBe('knowledge');
    // null fields should be cleaned by cleanObject or passed through
    expect(stix.last_execution_date).toBeNull();
    expect(stix.last_deleted_count).toBeNull();
    expect(stix.remaining_count).toBeNull();
  });

  it('should convert a file scope retention rule', () => {
    const instance = buildMockRetentionRule({
      name: 'File Cleanup Rule',
      scope: 'file',
      max_retention: 7,
      retention_unit: 'days',
    });
    const stix = convertRetentionRuleToStix(instance);

    expect(stix.name).toBe('File Cleanup Rule');
    expect(stix.scope).toBe('file');
    expect(stix.max_retention).toBe(7);
    expect(stix.retention_unit).toBe('days');
  });

  it('should convert a workbench scope retention rule', () => {
    const instance = buildMockRetentionRule({
      name: 'Workbench Cleanup Rule',
      scope: 'workbench',
      max_retention: 14,
      retention_unit: 'hours',
    });
    const stix = convertRetentionRuleToStix(instance);

    expect(stix.name).toBe('Workbench Cleanup Rule');
    expect(stix.scope).toBe('workbench');
    expect(stix.max_retention).toBe(14);
    expect(stix.retention_unit).toBe('hours');
  });

  it('should convert a rule with minutes retention unit', () => {
    const instance = buildMockRetentionRule({
      max_retention: 120,
      retention_unit: 'minutes',
    });
    const stix = convertRetentionRuleToStix(instance);

    expect(stix.max_retention).toBe(120);
    expect(stix.retention_unit).toBe('minutes');
  });

  it('should preserve complex filter strings', () => {
    const complexFilters = JSON.stringify({
      mode: 'and',
      filters: [
        { key: 'entity_type', values: ['Malware'], operator: 'eq', mode: 'or' },
        { key: 'created_at', values: ['2025-01-01T00:00:00.000Z'], operator: 'lt', mode: 'or' },
      ],
      filterGroups: [],
    });
    const instance = buildMockRetentionRule({ filters: complexFilters });
    const stix = convertRetentionRuleToStix(instance);

    expect(stix.filters).toBe(complexFilters);
    // Verify the JSON is valid and contains expected structure
    const parsed = JSON.parse(stix.filters);
    expect(parsed.mode).toBe('and');
    expect(parsed.filters).toHaveLength(2);
  });
});
