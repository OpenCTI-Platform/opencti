import { describe, expect, it } from 'vitest';
import { createTheme, getContrastRatio, type ThemeOptions } from '@mui/material/styles';
import ThemeDark from '../../../../components/ThemeDark';
import ThemeLight from '../../../../components/ThemeLight';
import type { Theme } from '../../../../components/Theme';
import {
  ALL_DEFENSE_LAYERS,
  computeLayerLevel,
  DEFAULT_DEFENSE_SCOPE,
  DEFENSE_AGGREGATE_PLATFORM,
  DEFENSE_UNCOVERED_LEVELS,
  defenseFailedColor,
  defenseGapsExportFileName,
  defenseLevelColor,
  defenseLevelTextColor,
  defenseThreatColor,
  defenseValidationGapsCount,
  defenseValidationTargets,
  isDisplayedValidationFailed,
  isThreatOverlayActive,
  isValidationFailed,
  MAX_VALIDATION_GAPS,
  MAX_VALIDATION_TECHNIQUES,
  parseDefenseScope,
  scopedDefensePlatforms,
  summarizeLevels,
  tacticDisplayName,
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
  describe('scopedDefensePlatforms', () => {
    it('keeps only the saved platforms that still exist, in the saved order', () => {
      const platforms = [{ id: 'edr', name: 'EDR' }, { id: 'siem', name: 'SIEM' }];
      expect(scopedDefensePlatforms(['siem', 'deleted', 'edr'], platforms)).toEqual([{ id: 'siem', name: 'SIEM' }, { id: 'edr', name: 'EDR' }]);
      expect(scopedDefensePlatforms(['deleted'], platforms)).toEqual([]);
    });
  });
  describe('isDisplayedValidationFailed', () => {
    it('reads the displayed platform entries of a result attributed to platforms', () => {
      expect(isDisplayedValidationFailed({ status: 'detected', platforms: [{ status: 'detected' }, { status: 'failed' }] })).toBe(true);
      expect(isDisplayedValidationFailed({ status: 'failed', platforms: [{ status: 'prevented' }] })).toBe(false);
    });
    it('reads the technique-wide status of an unattributed result', () => {
      expect(isDisplayedValidationFailed({ status: 'failed', platforms: [] })).toBe(true);
      expect(isDisplayedValidationFailed({ status: 'detected', platforms: [] })).toBe(false);
    });
  });
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

    it('treats the levels below a deployed detection as uncovered', () => {
      // A deployed detection not validated yet (level 3) is an open gap but not an uncovered technique
      expect(DEFENSE_UNCOVERED_LEVELS).toEqual([0, 1, 2]);
    });
  });

  describe('defense colours', () => {
    const themes = [
      ['dark', createTheme(ThemeDark() as ThemeOptions) as unknown as Theme],
      ['light', createTheme(ThemeLight() as ThemeOptions) as unknown as Theme],
    ] as const;
    it.each(themes)('resolves five distinct level colours from the %s theme tokens', (_, theme) => {
      const colors = [0, 1, 2, 3, 4].map((level) => defenseLevelColor(theme, level));
      expect(new Set(colors).size).toBe(5);
      colors.forEach((color) => expect(color).toMatch(/^#|^rgb/));
      expect(defenseLevelColor(theme, 12)).toBe(colors[0]);
      expect(defenseFailedColor(theme)).not.toBe(colors[4]);
      expect(defenseThreatColor(theme)).not.toBe(colors[0]);
    });
    it.each(themes)('keeps every level label readable (WCAG AA) on the %s theme', (_, theme) => {
      [0, 1, 2, 3, 4].forEach((level) => {
        const background = defenseLevelColor(theme, level);
        expect(getContrastRatio(background, defenseLevelTextColor(theme, background))).toBeGreaterThanOrEqual(4.5);
      });
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

  describe('isThreatOverlayActive', () => {
    it('reads the overlay from the scope, whatever the threats it currently matches', () => {
      expect(isThreatOverlayActive(DEFAULT_DEFENSE_SCOPE)).toBe(true);
      expect(isThreatOverlayActive({
        ...DEFAULT_DEFENSE_SCOPE,
        threatMode: 'SELECTED',
        threats: [{ value: 'intrusion-set-id', label: 'APT29', type: 'Intrusion-Set' }],
      })).toBe(true);
      expect(isThreatOverlayActive({ ...DEFAULT_DEFENSE_SCOPE, threatMode: 'NONE' })).toBe(false);
    });
    it('reads an empty selection or an empty filter as no overlay', () => {
      expect(isThreatOverlayActive({ ...DEFAULT_DEFENSE_SCOPE, threatMode: 'SELECTED' })).toBe(false);
      expect(isThreatOverlayActive({ ...DEFAULT_DEFENSE_SCOPE, threatMode: 'FILTERED' })).toBe(false);
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

  describe('defenseValidationTargets', () => {
    const technique = (id: string, level: number, threats: number) => ({ id, level, threats_count: threats });

    it('keeps the unvalidated techniques, the ones used by the most threats first', () => {
      const cells = [technique('a', 0, 1), technique('b', 4, 9), technique('c', 2, 5), technique('d', 3, 0)];
      expect(defenseValidationTargets(cells, false)).toEqual({ targets: [cells[2], cells[0], cells[3]], deferred: 0 });
      expect(defenseValidationTargets(cells, true)).toEqual({ targets: [cells[2], cells[0]], deferred: 0 });
    });

    it('counts the techniques a single request cannot hold instead of dropping them silently', () => {
      const cells = Array.from({ length: MAX_VALIDATION_TECHNIQUES + 57 }, (_, i) => technique(`t${i}`, 0, i));
      const { targets, deferred } = defenseValidationTargets(cells, false);
      expect(targets).toHaveLength(MAX_VALIDATION_TECHNIQUES);
      expect(targets[0].id).toBe(`t${MAX_VALIDATION_TECHNIQUES + 56}`);
      expect(deferred).toBe(57);
    });

    it('leaves the scope untouched', () => {
      const cells = [technique('a', 0, 1), technique('b', 0, 2)];
      defenseValidationTargets(cells, false);
      expect(cells.map((c) => c.id)).toEqual(['a', 'b']);
    });
  });

  describe('defenseValidationGapsCount', () => {
    it('counts every technique on all security platforms and on every requested platform', () => {
      expect(defenseValidationGapsCount(['ap-a', 'ap-b'], [], [])).toBe(2);
      expect(defenseValidationGapsCount(['ap-a', 'ap-b'], ['p1', 'p2'], [])).toBe(6);
    });

    it('counts a selected gap once, and never on the platform of another selected gap', () => {
      const gaps = [{ attackPatternId: 'ap-a', platformId: 'p1' }, { attackPatternId: 'ap-b', platformId: 'p2' }];
      expect(defenseValidationGapsCount(['ap-a', 'ap-b'], [], gaps)).toBe(4);
      expect(defenseValidationGapsCount(['ap-a', 'ap-b'], ['p1'], gaps)).toBe(5);
      expect(defenseValidationGapsCount(['ap-a'], [], [{ attackPatternId: 'ap-a', platformId: DEFENSE_AGGREGATE_PLATFORM }])).toBe(1);
    });

    it('goes over the limit of the platform with the largest technique selection on ten platforms', () => {
      const techniqueIds = Array.from({ length: MAX_VALIDATION_TECHNIQUES }, (_, i) => `t${i}`);
      const platformIds = Array.from({ length: 10 }, (_, i) => `p${i}`);
      expect(defenseValidationGapsCount(techniqueIds, platformIds.slice(0, 9), [])).toBe(MAX_VALIDATION_GAPS);
      expect(defenseValidationGapsCount(techniqueIds, platformIds, [])).toBeGreaterThan(MAX_VALIDATION_GAPS);
    });
  });

  describe('tacticDisplayName', () => {
    it('names an ATT&CK tactic from its kill chain phase slug', () => {
      expect(tacticDisplayName('reconnaissance')).toBe('Reconnaissance');
      expect(tacticDisplayName('resource-development')).toBe('Resource Development');
      expect(tacticDisplayName('initial-access')).toBe('Initial Access');
      expect(tacticDisplayName('command-and-control')).toBe('Command and Control');
    });

    it('keeps a phase name that is not a slug', () => {
      expect(tacticDisplayName('Actions on Objectives')).toBe('Actions on Objectives');
      expect(tacticDisplayName('Delivery')).toBe('Delivery');
    });
  });
});
