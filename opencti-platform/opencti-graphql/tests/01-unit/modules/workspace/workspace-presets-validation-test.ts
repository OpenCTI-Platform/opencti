import { describe, expect, it } from 'vitest';
import { buildDashboardPreset, removeVariableFromPresets } from '../../../../src/modules/workspace/workspace-presets-validation';
import { DASHBOARD_PRESETS_MAX_COUNT, type StoreDashboardPreset, type StoreDashboardVariable } from '../../../../src/modules/workspace/workspace-variables-types';

const SECTOR_ID = '11111111-1111-4111-8111-111111111111';
const CONFIDENCE_ID = '22222222-2222-4222-8222-222222222222';
const SINCE_ID = '33333333-3333-4333-8333-333333333333';
const PRESET_ID = '44444444-4444-4444-8444-444444444444';

const variables: StoreDashboardVariable[] = [
  { id: SECTOR_ID, name: 'Sector', type: 'entity', entityTypes: ['Sector'], restriction: { mode: 'none' }, defaultValue: 'sector-a' },
  { id: CONFIDENCE_ID, name: 'Min confidence', type: 'numeric', restriction: { mode: 'none' }, defaultValue: '50' },
  { id: SINCE_ID, name: 'Since', type: 'date', restriction: { mode: 'none' }, defaultValue: '2026-01-01T00:00:00.000Z' },
];
const existing: StoreDashboardPreset[] = [
  { id: PRESET_ID, name: 'Energy', values: { [SECTOR_ID]: 'sector-energy' }, config: { startDate: null, endDate: null, relativeDate: 'months-1' } },
];

describe('buildDashboardPreset', () => {
  it('should build a preset with a generated id, trimmed name, typed values and a normalized time range', () => {
    const preset = buildDashboardPreset({
      name: '  Finance ',
      values: [{ variableId: SECTOR_ID, value: 'sector-finance' }, { variableId: CONFIDENCE_ID, value: '80' }, { variableId: SINCE_ID, value: '' }],
      config: { relativeDate: 'days-7', startDate: '2026-01-01', endDate: null },
    }, existing, variables);
    expect(preset.id).toMatch(/^[0-9a-f-]{36}$/);
    expect(preset.name).toBe('Finance');
    // An empty value is not stored: the default of the variable applies.
    expect(preset.values).toEqual({ [SECTOR_ID]: 'sector-finance', [CONFIDENCE_ID]: '80' });
    // A relative date clears the absolute ones.
    expect(preset.config).toEqual({ relativeDate: 'days-7', startDate: null, endDate: null });
  });

  it('should keep an absolute range and accept a preset without values nor range', () => {
    const preset = buildDashboardPreset({ name: 'Q1', config: { startDate: '2026-01-01', endDate: '2026-03-31T23:59:59Z' } }, [], variables);
    expect(preset.config).toEqual({ relativeDate: null, startDate: '2026-01-01', endDate: '2026-03-31T23:59:59Z' });
    expect(buildDashboardPreset({ name: 'Empty' }, [], variables)).toMatchObject({ values: {}, config: { relativeDate: null, startDate: null, endDate: null } });
  });

  it('should update an existing preset by id and recreate a deleted one with a valid uuid', () => {
    const updated = buildDashboardPreset({ id: PRESET_ID, name: 'Energy & Utilities', values: [] }, existing, variables);
    expect(updated.id).toBe(PRESET_ID);
    const recreated = buildDashboardPreset({ id: '55555555-5555-4555-8555-555555555555', name: 'Back' }, existing, variables);
    expect(recreated.id).toBe('55555555-5555-4555-8555-555555555555');
    expect(() => buildDashboardPreset({ id: 'not-a-uuid', name: 'Bad' }, existing, variables)).toThrow('Invalid dashboard preset id');
  });

  it('should refuse a blank, too long or duplicated name', () => {
    expect(() => buildDashboardPreset({ name: '   ' }, existing, variables)).toThrow('Dashboard preset name is required');
    expect(() => buildDashboardPreset({ name: 'x'.repeat(201) }, existing, variables)).toThrow('Dashboard preset name is too long');
    expect(() => buildDashboardPreset({ name: ' energy ' }, existing, variables)).toThrow('A dashboard preset with this name already exists');
    // Renaming a preset to its own name is fine.
    expect(buildDashboardPreset({ id: PRESET_ID, name: 'ENERGY' }, existing, variables).name).toBe('ENERGY');
  });

  it('should refuse a value of an unknown variable, unless asked to drop it', () => {
    const values = [{ variableId: '99999999-9999-4999-8999-999999999999', value: 'x' }, { variableId: SECTOR_ID, value: 'sector-b' }];
    expect(() => buildDashboardPreset({ name: 'P', values }, [], variables)).toThrow('Unknown dashboard variable');
    expect(buildDashboardPreset({ name: 'P', values }, [], variables, { dropUnknownVariables: true }).values).toEqual({ [SECTOR_ID]: 'sector-b' });
  });

  it('should refuse a duplicated, token-shaped or ill-typed value', () => {
    expect(() => buildDashboardPreset({ name: 'P', values: [{ variableId: SECTOR_ID, value: 'a' }, { variableId: SECTOR_ID, value: 'b' }] }, [], variables))
      .toThrow('Duplicated dashboard preset value');
    expect(() => buildDashboardPreset({ name: 'P', values: [{ variableId: SECTOR_ID, value: `$var:${CONFIDENCE_ID}` }] }, [], variables))
      .toThrow('Invalid dashboard preset value');
    expect(() => buildDashboardPreset({ name: 'P', values: [{ variableId: CONFIDENCE_ID, value: 'high' }] }, [], variables))
      .toThrow('Invalid dashboard preset value');
    expect(() => buildDashboardPreset({ name: 'P', values: [{ variableId: SINCE_ID, value: '2026-02-30' }] }, [], variables))
      .toThrow('Invalid dashboard preset value');
  });

  it('should refuse an invalid time range', () => {
    expect(() => buildDashboardPreset({ name: 'P', config: { relativeDate: 'last-week' } }, [], variables)).toThrow('Invalid dashboard preset time range');
    expect(() => buildDashboardPreset({ name: 'P', config: { startDate: 'yesterday' } }, [], variables)).toThrow('Invalid dashboard preset time range');
  });

  it('should enforce the presets quota', () => {
    const many = Array.from({ length: DASHBOARD_PRESETS_MAX_COUNT }, (_, i) => ({ ...existing[0], id: `${i}`, name: `P${i}` }));
    expect(() => buildDashboardPreset({ name: 'One more' }, many, variables)).toThrow('A dashboard cannot hold more than 50 presets');
    // Updating one of them is still allowed.
    expect(buildDashboardPreset({ id: '3', name: 'Renamed' }, many, variables).id).toBe('3');
  });
});

describe('removeVariableFromPresets', () => {
  it('should drop the value of the variable from every preset and keep the others', () => {
    const presets: StoreDashboardPreset[] = [
      { id: 'a', name: 'A', values: { [SECTOR_ID]: 'x', [CONFIDENCE_ID]: '80' }, config: { startDate: null, endDate: null, relativeDate: null } },
      { id: 'b', name: 'B', values: { [CONFIDENCE_ID]: '90' }, config: { startDate: null, endDate: null, relativeDate: 'days-7' } },
    ];
    const result = removeVariableFromPresets(presets, SECTOR_ID);
    expect(result.map((preset) => preset.values)).toEqual([{ [CONFIDENCE_ID]: '80' }, { [CONFIDENCE_ID]: '90' }]);
    // The untouched preset is the same object.
    expect(result[1]).toBe(presets[1]);
  });
});
