import { describe, expect, it } from 'vitest';
import type { DashboardPreset, DashboardVariable } from '../dashboard-types';
import { isPresetModified, presetEffectiveValues, presetFromGraphql, presetInputFromValues } from './dashboardPresets';

const SECTOR_ID = '11111111-1111-4111-8111-111111111111';
const CONFIDENCE_ID = '22222222-2222-4222-8222-222222222222';
const variables: DashboardVariable[] = [
  { id: SECTOR_ID, name: 'Sector', type: 'entity', entityTypes: ['Sector'], restriction: { mode: 'none' }, defaultValue: 'sector-a' },
  { id: CONFIDENCE_ID, name: 'Min confidence', type: 'numeric', restriction: { mode: 'none' }, defaultValue: '50' },
];
const defaults = new Map([[SECTOR_ID, 'sector-a'], [CONFIDENCE_ID, '50']]);
const preset: DashboardPreset = {
  id: 'p1',
  name: 'Energy',
  values: { [SECTOR_ID]: 'sector-energy', gone: 'x' },
  config: { startDate: null, endDate: null, relativeDate: 'months-1' },
};

describe('presetFromGraphql', () => {
  it('turns the values list into a record and completes the range', () => {
    expect(presetFromGraphql({ id: 'p', name: 'P', values: [{ variableId: SECTOR_ID, value: 'x' }], config: { relativeDate: 'days-7' } }))
      .toEqual({ id: 'p', name: 'P', values: { [SECTOR_ID]: 'x' }, config: { startDate: null, endDate: null, relativeDate: 'days-7' } });
  });
});

describe('presetEffectiveValues', () => {
  it('takes the preset value, else the default, and ignores unknown variables', () => {
    expect(presetEffectiveValues(preset, variables, defaults)).toEqual(new Map([[SECTOR_ID, 'sector-energy'], [CONFIDENCE_ID, '50']]));
  });
});

describe('isPresetModified', () => {
  const expected = new Map([[SECTOR_ID, 'sector-energy'], [CONFIDENCE_ID, '50']]);
  it('is false when the values and the range are the ones of the preset', () => {
    expect(isPresetModified(preset, variables, defaults, expected, preset.config)).toBe(false);
  });
  it('is true when a value or the range changed', () => {
    expect(isPresetModified(preset, variables, defaults, new Map([...expected, [CONFIDENCE_ID, '80']]), preset.config)).toBe(true);
    expect(isPresetModified(preset, variables, defaults, expected, { startDate: null, endDate: null, relativeDate: 'days-7' })).toBe(true);
  });
});

describe('presetInputFromValues', () => {
  it('builds the upsert input from the current values and range, with the id when updating', () => {
    const values = new Map([[SECTOR_ID, 'sector-energy'], [CONFIDENCE_ID, '']]);
    const range = { startDate: '2026-01-01', endDate: null, relativeDate: null };
    expect(presetInputFromValues('Energy', variables, values, range)).toEqual({
      name: 'Energy',
      values: [{ variableId: SECTOR_ID, value: 'sector-energy' }],
      config: { startDate: '2026-01-01', endDate: null, relativeDate: null },
    });
    expect(presetInputFromValues('Energy', variables, values, range, 'p1').id).toBe('p1');
  });
});
