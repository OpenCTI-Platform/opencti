import { getContrastRatio } from '@mui/material/styles';
import type { Theme } from '../../../../components/Theme';
import type { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import { isFilterGroupNotEmpty, serializeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';

export const DEFENSE_LEVEL_NONE = 0;
export const DEFENSE_LEVEL_TELEMETRY = 1;
export const DEFENSE_LEVEL_DETECTION_AVAILABLE = 2;
export const DEFENSE_LEVEL_DETECTION_DEPLOYED = 3;
export const DEFENSE_LEVEL_VALIDATED = 4;
export const DEFENSE_LEVELS = [
  DEFENSE_LEVEL_NONE,
  DEFENSE_LEVEL_TELEMETRY,
  DEFENSE_LEVEL_DETECTION_AVAILABLE,
  DEFENSE_LEVEL_DETECTION_DEPLOYED,
  DEFENSE_LEVEL_VALIDATED,
] as const;
// A technique counts as covered once a detection is live on a security platform.
export const DEFENSE_COVERED_LEVEL = DEFENSE_LEVEL_DETECTION_DEPLOYED;
// The gaps API also returns deployed detections that are not validated yet, so "uncovered" asks for these levels.
export const DEFENSE_UNCOVERED_LEVELS: number[] = DEFENSE_LEVELS.filter((level) => level < DEFENSE_COVERED_LEVEL);

/** The saved platforms of a scope that still exist and are visible, as the matrix shows them. */
export const scopedDefensePlatforms = (
  platformIds: ReadonlyArray<string>,
  platforms: ReadonlyArray<{ readonly id: string; readonly name: string }>,
) => platformIds.flatMap((id) => {
  const platform = platforms.find((p) => p.id === id);
  return platform ? [{ id: platform.id, name: platform.name }] : [];
});

/**
 * Whether a result failed in the displayed cell: a result attributed to the displayed platforms fails through their
 * entries, an unattributed one through its technique-wide status.
 */
export const isDisplayedValidationFailed = (validation: {
  readonly status: string;
  readonly platforms: ReadonlyArray<{ readonly status: string }>;
}) => (validation.platforms.length > 0
  ? validation.platforms.some((platform) => platform.status === 'failed')
  : validation.status === 'failed');

export const DEFENSE_LEVEL_LABELS: Record<number, string> = {
  [DEFENSE_LEVEL_NONE]: 'No coverage',
  [DEFENSE_LEVEL_TELEMETRY]: 'Telemetry only',
  [DEFENSE_LEVEL_DETECTION_AVAILABLE]: 'Detection available',
  [DEFENSE_LEVEL_DETECTION_DEPLOYED]: 'Detection deployed',
  [DEFENSE_LEVEL_VALIDATED]: 'Detection validated',
};

type Translate = (message: string, options?: { values?: Record<string, string | number> }) => string;

// The one wording of a level, used by every chip, legend, filter option and caption
export const defenseLevelLabel = (t_i18n: Translate, level: number) => t_i18n('Level {level} - {label}', {
  values: { level, label: t_i18n(DEFENSE_LEVEL_LABELS[level] ?? DEFENSE_LEVEL_LABELS[DEFENSE_LEVEL_NONE]) },
});

export const DEFENSE_LEVEL_DESCRIPTIONS: Record<number, string> = {
  [DEFENSE_LEVEL_NONE]: 'No telemetry, detection rule or validation is known for this technique.',
  [DEFENSE_LEVEL_TELEMETRY]: 'A security platform collects a data component that detects this technique.',
  [DEFENSE_LEVEL_DETECTION_AVAILABLE]: 'A detection rule indicating this technique is known in the platform.',
  [DEFENSE_LEVEL_DETECTION_DEPLOYED]: 'A detection rule indicating this technique is deployed on a security platform.',
  [DEFENSE_LEVEL_VALIDATED]: 'OpenAEV proved the detection or the prevention of this technique.',
};

// Data colours of the five levels, from nothing to proven, of a failed validation and of the threat outline.
// The design system has no sequential data scale yet (see fds-migration/TOKEN-MAPPING.md): the closest
// design-system hues bridged into the theme are used, identical in both themes.
const levelColorOf = (theme: Theme): Record<number, string> => {
  const { tertiary, alert } = theme.palette.designSystem;
  return {
    [DEFENSE_LEVEL_NONE]: tertiary.grey?.[400] ?? alert.info.secondary,
    [DEFENSE_LEVEL_TELEMETRY]: tertiary.orange?.[400] ?? alert.warning.primary,
    [DEFENSE_LEVEL_DETECTION_AVAILABLE]: tertiary.yellow?.[400] ?? alert.alert.primary,
    [DEFENSE_LEVEL_DETECTION_DEPLOYED]: tertiary.green?.[400] ?? alert.success.secondary,
    [DEFENSE_LEVEL_VALIDATED]: tertiary.green?.[600] ?? alert.success.primary,
  };
};

export const defenseLevelColor = (theme: Theme, level: number): string => {
  const colors = levelColorOf(theme);
  return colors[level] ?? colors[DEFENSE_LEVEL_NONE];
};

export const defenseFailedColor = (theme: Theme): string => theme.palette.designSystem.tertiary.red?.[500] ?? theme.palette.designSystem.alert.error.primary;

export const defenseThreatColor = (theme: Theme): string => theme.palette.designSystem.tertiary.darkBlue?.[300] ?? theme.palette.designSystem.secondary.main;

/**
 * Text colour of a label drawn on a level colour: the one of black and white with the highest contrast,
 * at least 4.5:1 (WCAG AA) on every level colour of both themes.
 */
export const defenseLevelTextColor = (theme: Theme, background: string): string => {
  const { black = 'black', white = 'white' } = theme.palette.common;
  return getContrastRatio(background, black) >= getContrastRatio(background, white) ? black : white;
};

export type DefenseDetection = 'none' | 'available' | 'deployed' | 'active';
export type DefenseValidation = 'none' | 'prevented' | 'detected' | 'failed';
export type DefenseAction = 'add_telemetry' | 'import_rule' | 'deploy_rule' | 'activate_rule' | 'validate' | 'fix_detection' | 'none';

export const DEFENSE_DETECTION_LABELS: Record<DefenseDetection, string> = {
  none: 'No detection',
  available: 'Rule available',
  deployed: 'Rule deployed',
  active: 'Rule active',
};

export const DEFENSE_VALIDATION_LABELS: Record<DefenseValidation, string> = {
  none: 'Not validated',
  prevented: 'Prevented',
  detected: 'Detected',
  failed: 'Validation failed',
};

export const DEFENSE_ACTION_LABELS: Record<DefenseAction, string> = {
  add_telemetry: 'Add telemetry',
  import_rule: 'Import a detection rule',
  deploy_rule: 'Deploy a detection rule',
  activate_rule: 'Activate the deployed rule',
  validate: 'Validate in OpenAEV',
  fix_detection: 'Fix the detection',
  none: 'No action needed',
};

// Deployment lifecycle of a rule on a security platform (deployed-on relationship)
export const DEFENSE_DEPLOYMENT_STATUS_LABELS: Record<string, string> = {
  pending: 'Pending',
  deployed: 'Deployed',
  active: 'Active',
  failed: 'Failed',
  removed: 'Removed',
  expired: 'Expired',
};

export const DEFENSE_ACTIONS: DefenseAction[] = ['add_telemetry', 'import_rule', 'deploy_rule', 'activate_rule', 'validate', 'fix_detection'];

export type DefenseLayer = 'telemetry' | 'detection' | 'validated' | 'mitigations';
export const DEFENSE_LAYERS: DefenseLayer[] = ['telemetry', 'detection', 'validated', 'mitigations'];
export const DEFENSE_LAYER_LABELS: Record<DefenseLayer, string> = {
  telemetry: 'Telemetry',
  detection: 'Detection',
  validated: 'Validation',
  mitigations: 'Mitigations',
};
export type DefenseLayersState = Record<DefenseLayer, boolean>;
export const ALL_DEFENSE_LAYERS: DefenseLayersState = { telemetry: true, detection: true, validated: true, mitigations: true };

export interface DefenseCellLike {
  readonly level: number;
  readonly telemetry: boolean;
  readonly detection: string;
  readonly validated: string;
  readonly mitigated?: boolean;
}

const isValidationSuccess = (validated: string) => validated === 'prevented' || validated === 'detected';

/**
 * Level of a cell restricted to the enabled layers. With every evidence layer enabled the level
 * computed by the platform is kept as is, so that the matrix never contradicts the backlog.
 * Mitigations never change the level: they are an overlay.
 */
export const computeLayerLevel = (cell: DefenseCellLike, layers: DefenseLayersState): number => {
  if (layers.telemetry && layers.detection && layers.validated) {
    return cell.level;
  }
  let level = DEFENSE_LEVEL_NONE;
  if (layers.telemetry && cell.telemetry) {
    level = DEFENSE_LEVEL_TELEMETRY;
  }
  if (layers.detection) {
    if (cell.detection === 'available') {
      level = Math.max(level, DEFENSE_LEVEL_DETECTION_AVAILABLE);
    }
    if (cell.detection === 'deployed' || cell.detection === 'active') {
      level = Math.max(level, DEFENSE_LEVEL_DETECTION_DEPLOYED);
    }
  }
  if (layers.validated) {
    if (isValidationSuccess(cell.validated)) {
      level = DEFENSE_LEVEL_VALIDATED;
    } else if (cell.validated === 'failed') {
      level = Math.min(level, DEFENSE_LEVEL_DETECTION_AVAILABLE);
    }
  }
  return level;
};

export const isValidationFailed = (cell: DefenseCellLike, layers: DefenseLayersState) => layers.validated && cell.validated === 'failed';

export interface DefenseLevelsSummary {
  total: number;
  covered: number;
  percent: number;
}

/**
 * Coverage of a distribution of techniques per level (index = level): the share of techniques
 * with a deployed or validated detection, rounded to the unit.
 */
export const summarizeLevels = (levels: ReadonlyArray<number>): DefenseLevelsSummary => {
  const total = levels.reduce((sum, count) => sum + count, 0);
  const covered = levels.slice(DEFENSE_COVERED_LEVEL).reduce((sum, count) => sum + count, 0);
  return { total, covered, percent: total === 0 ? 0 : Math.round((covered / total) * 100) };
};

// region threat scope
export const DEFENSE_THREAT_TYPES = ['Intrusion-Set', 'Threat-Actor-Group', 'Threat-Actor-Individual', 'Campaign', 'Malware'];
export type DefenseThreatScopeMode = 'ALL' | 'SELECTED' | 'FILTERED' | 'NONE';
export const DEFENSE_THREAT_SCOPE_MODES: DefenseThreatScopeMode[] = ['ALL', 'SELECTED', 'FILTERED', 'NONE'];
export const DEFENSE_THREAT_SCOPE_LABELS: Record<DefenseThreatScopeMode, string> = {
  ALL: 'All threats',
  SELECTED: 'Selected threats',
  FILTERED: 'Filtered threats',
  NONE: 'No threat overlay',
};
export interface DefenseThreatOption {
  value: string;
  label: string;
  type: string;
}
export interface DefenseScopeState {
  platformIds: string[];
  threatMode: DefenseThreatScopeMode;
  threats: DefenseThreatOption[];
  threatFilters: FilterGroup | null;
}
export const DEFAULT_DEFENSE_SCOPE: DefenseScopeState = { platformIds: [], threatMode: 'ALL', threats: [], threatFilters: null };

/**
 * GraphQL threat scope of a scope state. A selection without threats, or a filtered scope
 * without filters, means no threat overlay rather than every threat.
 */
export const toThreatScopeInput = (scope: DefenseScopeState) => {
  if (scope.threatMode === 'SELECTED') {
    if (scope.threats.length === 0) {
      return { mode: 'NONE' as const };
    }
    return { mode: 'SELECTED' as const, threatIds: scope.threats.map((t) => t.value) };
  }
  if (scope.threatMode === 'FILTERED') {
    if (!scope.threatFilters || !isFilterGroupNotEmpty(scope.threatFilters)) {
      return { mode: 'NONE' as const };
    }
    return { mode: 'FILTERED' as const, filters: JSON.parse(serializeFilterGroupForBackend(scope.threatFilters)) };
  }
  return { mode: scope.threatMode };
};

/** Whether the scope overlays threats, including a scope whose threats currently match nothing. */
export const isThreatOverlayActive = (scope: DefenseScopeState) => toThreatScopeInput(scope).mode !== 'NONE';

const isString = (value: unknown): value is string => typeof value === 'string';

const isFilterGroupShape = (value: unknown): value is FilterGroup => {
  if (!value || typeof value !== 'object') return false;
  const group = value as Partial<FilterGroup>;
  return isString(group.mode) && Array.isArray(group.filters) && Array.isArray(group.filterGroups);
};

/**
 * Reads a persisted scope defensively: anything malformed falls back to the default scope.
 */
export const parseDefenseScope = (raw: string | null): DefenseScopeState => {
  if (!raw) return DEFAULT_DEFENSE_SCOPE;
  try {
    const parsed = JSON.parse(raw) as Partial<DefenseScopeState>;
    const threatMode = DEFENSE_THREAT_SCOPE_MODES.find((mode) => mode === parsed.threatMode) ?? 'ALL';
    const platformIds = Array.isArray(parsed.platformIds) ? parsed.platformIds.filter(isString) : [];
    const threats = Array.isArray(parsed.threats)
      ? parsed.threats.filter((t): t is DefenseThreatOption => !!t && isString(t.value) && isString(t.label) && isString(t.type))
      : [];
    const threatFilters = isFilterGroupShape(parsed.threatFilters) ? parsed.threatFilters : null;
    return { platformIds, threatMode, threats, threatFilters };
  } catch {
    return DEFAULT_DEFENSE_SCOPE;
  }
};
// endregion

// region export
// Maximum number of gaps in an export, the one the API applies
export const DEFENSE_GAPS_EXPORT_MAX = 10000;

export const defenseGapsExportFileName = (date: Date) => `defense_gaps_${date.toISOString().substring(0, 10)}.csv`;

export const downloadCsv = (content: string, fileName: string) => {
  const blob = new Blob([content], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = fileName;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
};
// endregion
