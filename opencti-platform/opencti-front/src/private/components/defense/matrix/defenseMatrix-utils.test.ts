import { describe, expect, it } from 'vitest';
import {
  ALL_DEFENSE_LAYERS,
  computeLayerLevel,
  DEFAULT_DEFENSE_SCOPE,
  DEFENSE_LEVEL_COLORS,
  defenseGapsExportFileName,
  defenseLevelColor,
  isValidationFailed,
  parseDefenseScope,
  summarizeLevels,
  toThreatScopeInput,
} from './defenseMatrix-utils';

const cell = (overrides: Partial<Parameters<typeof computeLayerLevel>[0]> = {}) => ({
  level: 0,
  telemetry: false,
  detection: 'none',
  validated: 'none',
  mitigated: false,
  ...overrides,
});

describe('defenseMatrix-utils', () => {
  describe('computeLayerLevel', () => {
    it('keeps the platform level when every evidence layer is enabled', () => {
      expect(computeLayerLevel(cell({ level: 3, telemetry: true, detection: 'deployed' }), ALL_DEFENSE_LAYERS)).toBe(3);
      // the mitigation overlay never changes the level
      expect(computeLayerLevel(cell({ level: 2 }), { ...ALL_DEFENSE_LAYERS, mitigations: false })).toBe(2);
    });

    it('restricts the level to the telemetry layer', () => {
      const layers = { telemetry: true, detection: false, validated: false, mitigations: true };
      expect(computeLayerLevel(cell({ level: 4, telemetry: true, detection: 'active', validated: 'detected' }), layers)).toBe(1);
      expect(computeLayerLevel(cell({ level: 2, detection: 'available' }), layers)).toBe(0);
    });

    it('restricts the level to the detection layer', () => {
      const layers = { telemetry: false, detection: true, validated: false, mitigations: false };
      expect(computeLayerLevel(cell({ level: 2, telemetry: true, detection: 'available' }), layers)).toBe(2);
      expect(computeLayerLevel(cell({ level: 3, detection: 'deployed' }), layers)).toBe(3);
      expect(computeLayerLevel(cell({ level: 4, detection: 'active', validated: 'prevented' }), layers)).toBe(3);
    });

    it('raises to validated on a successful validation and caps a failed one at detection available', () => {
      const layers = { telemetry: true, detection: true, validated: false, mitigations: false };
      const withValidation = { ...layers, validated: true };
      expect(computeLayerLevel(cell({ level: 4, telemetry: true, detection: 'deployed', validated: 'detected' }), layers)).toBe(3);
      expect(computeLayerLevel(cell({ validated: 'prevented' }), { telemetry: false, detection: false, validated: true, mitigations: false })).toBe(4);
      expect(computeLayerLevel(cell({ telemetry: true, detection: 'active', validated: 'failed' }), { ...withValidation, mitigations: false, telemetry: false })).toBe(2);
    });
  });

  describe('isValidationFailed', () => {
    it('only reports a failed validation when the validation layer is enabled', () => {
      expect(isValidationFailed(cell({ validated: 'failed' }), ALL_DEFENSE_LAYERS)).toBe(true);
      expect(isValidationFailed(cell({ validated: 'failed' }), { ...ALL_DEFENSE_LAYERS, validated: false })).toBe(false);
      expect(isValidationFailed(cell({ validated: 'detected' }), ALL_DEFENSE_LAYERS)).toBe(false);
    });
  });

  describe('summarizeLevels', () => {
    it('counts the techniques with a deployed or validated detection', () => {
      expect(summarizeLevels([4, 3, 1, 1, 1])).toEqual({ total: 10, covered: 2, percent: 20 });
      expect(summarizeLevels([0, 0, 0, 0, 0])).toEqual({ total: 0, covered: 0, percent: 0 });
      expect(summarizeLevels([1, 0, 0, 1, 1])).toEqual({ total: 3, covered: 2, percent: 67 });
    });
  });

  describe('defenseLevelColor', () => {
    it('returns the color of the level and falls back to no coverage', () => {
      expect(defenseLevelColor(4)).toBe(DEFENSE_LEVEL_COLORS[4]);
      expect(defenseLevelColor(12)).toBe(DEFENSE_LEVEL_COLORS[0]);
    });
  });

  describe('toThreatScopeInput', () => {
    it('maps every threat scope mode', () => {
      expect(toThreatScopeInput(DEFAULT_DEFENSE_SCOPE)).toEqual({ mode: 'ALL' });
      expect(toThreatScopeInput({ ...DEFAULT_DEFENSE_SCOPE, threatMode: 'NONE' })).toEqual({ mode: 'NONE' });
      expect(toThreatScopeInput({
        ...DEFAULT_DEFENSE_SCOPE,
        threatMode: 'SELECTED',
        threats: [{ value: 'intrusion-set-id', label: 'APT29', type: 'Intrusion-Set' }],
      })).toEqual({ mode: 'SELECTED', threatIds: ['intrusion-set-id'] });
    });

    it('never widens an empty selection or an empty filter to every threat', () => {
      expect(toThreatScopeInput({ ...DEFAULT_DEFENSE_SCOPE, threatMode: 'SELECTED' })).toEqual({ mode: 'NONE' });
      expect(toThreatScopeInput({ ...DEFAULT_DEFENSE_SCOPE, threatMode: 'FILTERED' })).toEqual({ mode: 'NONE' });
    });

    it('sends the filters of a filtered scope in the backend format', () => {
      const input = toThreatScopeInput({
        ...DEFAULT_DEFENSE_SCOPE,
        threatMode: 'FILTERED',
        threatFilters: {
          mode: 'and',
          filters: [{ key: 'entity_type', values: ['Intrusion-Set'], operator: 'eq', mode: 'or' }],
          filterGroups: [],
        },
      });
      expect(input.mode).toBe('FILTERED');
      expect((input as { filters: { filters: { key: string[] }[] } }).filters.filters[0].key).toEqual(['entity_type']);
    });
  });

  describe('parseDefenseScope', () => {
    it('reads a persisted scope', () => {
      const scope = { platformIds: ['p1'], threatMode: 'SELECTED', threats: [{ value: 't1', label: 'T1', type: 'Campaign' }], threatFilters: null };
      expect(parseDefenseScope(JSON.stringify(scope))).toEqual(scope);
    });

    it('falls back to the default scope on malformed data', () => {
      expect(parseDefenseScope(null)).toEqual(DEFAULT_DEFENSE_SCOPE);
      expect(parseDefenseScope('{not json')).toEqual(DEFAULT_DEFENSE_SCOPE);
      expect(parseDefenseScope(JSON.stringify({ platformIds: [1, 'p2'], threatMode: 'EVERYTHING', threats: [{ value: 1 }], threatFilters: 'x' })))
        .toEqual({ platformIds: ['p2'], threatMode: 'ALL', threats: [], threatFilters: null });
    });
  });

  describe('defenseGapsExportFileName', () => {
    it('names the export after the day', () => {
      expect(defenseGapsExportFileName(new Date('2026-10-03T12:00:00Z'))).toBe('defense_gaps_2026-10-03.csv');
    });
  });
});
