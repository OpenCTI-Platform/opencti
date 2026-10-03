import type { ChipSeverity } from '@filigran/design-system';
import type { FieldOption } from '../../../utils/field';
import { HUNT_SCHEDULE_MANUAL, HUNT_SCHEDULE_STANDING, type HuntScheduleMode, huntScheduleMode } from './hunt-schedule-utils';

export const HUNT_ENTITY_TYPE = 'Hunt';
export const HUNT_RUN_ENTITY_TYPE = 'Hunt-Run';

export const HUNT_TYPES = ['telemetry', 'infrastructure'] as const;
export const HUNT_STATUSES = ['draft', 'active', 'paused', 'retired'] as const;
export const HUNT_SOURCE_KINDS = ['analyst', 'agent', 'hub'] as const;
export const HUNT_RUN_STATUSES = ['queued', 'running', 'completed', 'failed', 'timeout'] as const;
export const HUNT_RUN_TRIGGERS = ['manual', 'schedule', 'standing', 'playbook', 'emulation', 'preview', 'retry'] as const;
export const HUNT_RUN_VERDICTS = ['pending', 'true_positive', 'benign', 'inconclusive'] as const;
export const HUNT_ANALYST_VERDICTS = ['true_positive', 'benign', 'inconclusive'] as const;

export type HuntTypeValue = typeof HUNT_TYPES[number];
export type HuntStatusValue = typeof HUNT_STATUSES[number];
export type HuntSourceKindValue = typeof HUNT_SOURCE_KINDS[number];
export type HuntRunStatusValue = typeof HUNT_RUN_STATUSES[number];
export type HuntRunTriggerValue = typeof HUNT_RUN_TRIGGERS[number];
export type HuntRunVerdictValue = typeof HUNT_RUN_VERDICTS[number];

export const HUNT_PLATFORM_INTERNET = 'internet';
export const HUNT_PLATFORMS = [
  'splunk',
  'microsoft-sentinel',
  'elastic-security',
  'crowdstrike-logscale',
  'google-secops',
  'opensearch',
  'clickhouse',
  's3-ocsf',
  HUNT_PLATFORM_INTERNET,
] as const;
export const HUNT_QUERY_LANGUAGES = [
  'spl',
  'kql',
  'esql',
  'lucene',
  'eql',
  'logscale',
  'yara-l',
  'udm',
  'ppl',
  'opensearch-lucene',
  'sql',
  'internet',
] as const;
/** Default query language of each platform, offered first when a native query row is added */
export const HUNT_PLATFORM_DEFAULT_LANGUAGE: Record<string, string> = {
  splunk: 'spl',
  'microsoft-sentinel': 'kql',
  'elastic-security': 'esql',
  'crowdstrike-logscale': 'logscale',
  'google-secops': 'yara-l',
  opensearch: 'ppl',
  clickhouse: 'sql',
  's3-ocsf': 'sql',
  internet: 'internet',
};

export const HUNT_TARGET_TYPES = ['Intrusion-Set', 'Malware', 'Campaign', 'Threat-Actor-Group', 'Threat-Actor-Individual'];
export const HUNT_TECHNIQUE_TYPES = ['Attack-Pattern'];
export const HUNT_SOURCE_TYPES = ['Indicator', 'Report'];
export const HUNT_SCOPE_TYPES = ['SecurityPlatform'];

export const HUNT_DEFAULT_TIME_WINDOW_HOURS = 24;
export const HUNT_DEFAULT_ESCALATION_THRESHOLD = 10;
export const HUNT_MAX_TIME_WINDOW_HOURS = 720;
export const HUNT_MAX_ESCALATION_THRESHOLD = 1000000;
export const HUNT_MAX_RESULTS_PER_RUN = 10000;

export const HUNT_PLANNER_INTENT = 'cti.hunt_hypothesis';
export const HUNT_TRIAGE_INTENT = 'cti.hunt_triage';

// region labels and chip tones
export const huntStatusLabel = (status?: string | null) => {
  switch (status) {
    case 'draft': return 'Draft';
    case 'active': return 'Active';
    case 'paused': return 'Paused';
    case 'retired': return 'Retired';
    default: return 'Unknown';
  }
};

export const huntStatusSeverity = (status?: string | null): ChipSeverity => {
  switch (status) {
    case 'draft': return 'info';
    case 'active': return 'low';
    case 'paused': return 'medium';
    default: return 'neutral';
  }
};

export const huntTypeLabel = (huntType?: string | null) => (huntType === 'infrastructure' ? 'Infrastructure (outside-in)' : 'Telemetry (inside-out)');

export const huntSourceKindLabel = (sourceKind?: string | null) => {
  switch (sourceKind) {
    case 'agent': return 'AI agent';
    case 'hub': return 'XTM Hub';
    default: return 'Analyst';
  }
};

export const huntRunStatusLabel = (status?: string | null) => {
  switch (status) {
    case 'queued': return 'Queued';
    case 'running': return 'Running';
    case 'completed': return 'Completed';
    case 'failed': return 'Failed';
    case 'timeout': return 'Timeout';
    default: return 'Unknown';
  }
};

export const huntRunStatusSeverity = (status?: string | null): ChipSeverity => {
  switch (status) {
    case 'running': return 'info';
    case 'completed': return 'low';
    case 'timeout': return 'high';
    case 'failed': return 'critical';
    default: return 'neutral';
  }
};

export const huntRunTriggerLabel = (trigger?: string | null) => {
  switch (trigger) {
    case 'manual': return 'Manual';
    case 'schedule': return 'Schedule';
    case 'standing': return 'Standing';
    case 'playbook': return 'Playbook';
    case 'emulation': return 'Emulation';
    case 'preview': return 'Preview';
    case 'retry': return 'Retry';
    default: return 'Unknown';
  }
};

export const huntVerdictLabel = (verdict?: string | null) => {
  switch (verdict) {
    case 'true_positive': return 'True positive';
    case 'benign': return 'Benign';
    case 'inconclusive': return 'Inconclusive';
    case 'pending': return 'Pending';
    default: return 'Unknown';
  }
};

export const huntVerdictSeverity = (verdict?: string | null): ChipSeverity => {
  switch (verdict) {
    case 'true_positive': return 'critical';
    case 'benign': return 'low';
    case 'inconclusive': return 'medium';
    default: return 'neutral';
  }
};

export const huntVerdictSourceLabel = (source?: string | null) => {
  switch (source) {
    case 'auto': return 'Automatic';
    case 'agent': return 'AI agent';
    case 'analyst': return 'Analyst';
    default: return '-';
  }
};
// endregion

// region status transitions
export interface HuntStatusTransition {
  to: HuntStatusValue;
  label: string;
}

/** Lifecycle of a hunt: drafts never run, active hunts run, paused hunts keep their logic, retired hunts are archived. */
export const huntStatusTransitions = (status?: string | null): HuntStatusTransition[] => {
  switch (status) {
    case 'draft':
      return [{ to: 'active', label: 'Activate' }, { to: 'retired', label: 'Retire' }];
    case 'active':
      return [{ to: 'paused', label: 'Pause' }, { to: 'retired', label: 'Retire' }];
    case 'paused':
      return [{ to: 'active', label: 'Resume' }, { to: 'retired', label: 'Retire' }];
    case 'retired':
      return [{ to: 'draft', label: 'Reopen as draft' }];
    default:
      return [];
  }
};

/** Autonomous execution (any schedule but manual, PIR activation) is an Enterprise Edition capability. */
export const isAutonomousHunt = (hunt: { hunt_schedule?: string | null; hunt_pir_activation?: boolean | null }) => {
  return huntScheduleMode(hunt.hunt_schedule) !== 'manual' || hunt.hunt_pir_activation === true;
};

export const hasHuntLogic = (hunt: {
  hunt_type?: string | null;
  sigma_rule?: string | null;
  native_queries?: ReadonlyArray<{ platform: string }> | null;
}) => {
  const nativeQueries = hunt.native_queries ?? [];
  if (hunt.hunt_type === 'infrastructure') {
    return nativeQueries.some((nativeQuery) => nativeQuery.platform === HUNT_PLATFORM_INTERNET);
  }
  return (hunt.sigma_rule ?? '').trim().length > 0 || nativeQueries.some((nativeQuery) => nativeQuery.platform !== HUNT_PLATFORM_INTERNET);
};

/** Hunts proposed by an agent or imported from XTM Hub stay drafts until an analyst reviews them. */
export const isHuntPendingReview = (hunt: { hunt_source_kind?: string | null; hunt_status?: string | null }) => {
  return (hunt.hunt_source_kind === 'agent' || hunt.hunt_source_kind === 'hub') && hunt.hunt_status === 'draft';
};

/** The platform refuses to run (or retry) draft and retired hunts, and any hunt from inside a draft workspace; previews stay allowed. */
export const canStartHuntRun = (huntStatus: string | null | undefined, inDraftWorkspace: boolean) => {
  return !inDraftWorkspace && (huntStatus === 'active' || huntStatus === 'paused');
};

export const huntDraftWorkspacePath = (draftId: string) => `/dashboard/data/import/draft/${draftId}`;
// endregion

// region runs
export const HUNT_RUN_TERMINAL_STATUSES: string[] = ['completed', 'failed', 'timeout'];

export const isTerminalHuntRun = (status?: string | null) => HUNT_RUN_TERMINAL_STATUSES.includes(status ?? '');

export interface HuntRunCapabilityInput {
  hunt_run_status?: string | null;
  hunt_run_mode?: string | null;
}

export const canSetHuntRunVerdict = (run: HuntRunCapabilityInput) => run.hunt_run_mode !== 'preview' && run.hunt_run_status === 'completed';
export const canRetryHuntRun = (run: HuntRunCapabilityInput) => run.hunt_run_mode !== 'preview' && isTerminalHuntRun(run.hunt_run_status);
export const canTriageHuntRun = (run: HuntRunCapabilityInput) => run.hunt_run_mode !== 'preview' && run.hunt_run_status === 'completed';

export const formatHuntRunDuration = (costMs?: number | null): string | null => {
  if (costMs === null || costMs === undefined || costMs < 0) {
    return null;
  }
  if (costMs < 1000) {
    return `${costMs} ms`;
  }
  const seconds = costMs / 1000;
  if (seconds < 60) {
    return `${seconds.toFixed(seconds < 10 ? 1 : 0)} s`;
  }
  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = Math.round(seconds % 60);
  return `${minutes} min ${remainingSeconds} s`;
};
// endregion

// region scope
interface StoredFilter {
  key: string | string[];
  values: unknown[];
  operator?: string;
  mode?: string;
}
interface StoredFilterGroup {
  mode?: string;
  filters?: StoredFilter[];
  filterGroups?: StoredFilterGroup[];
}

/** The hunt scope is a filter group over Security Platforms, stored as JSON; an empty scope means every platform. */
export const buildHuntScope = (platformIds: string[]): string => {
  if (platformIds.length === 0) {
    return '';
  }
  return JSON.stringify({
    mode: 'and',
    filters: [{ key: ['id'], values: platformIds, operator: 'eq', mode: 'or' }],
    filterGroups: [],
  });
};

/**
 * Security Platform ids of a scope built by this form. Returns an empty list for an empty scope,
 * and null for a scope that is not a plain list of platforms (written by an API client or a playbook).
 */
export const parseHuntScopePlatformIds = (scope?: string | null): string[] | null => {
  if (!scope || scope.trim().length === 0) {
    return [];
  }
  let parsed: StoredFilterGroup;
  try {
    parsed = JSON.parse(scope) as StoredFilterGroup;
  } catch {
    return null;
  }
  const filters = parsed.filters ?? [];
  if ((parsed.filterGroups ?? []).length > 0 || filters.length > 1) {
    return null;
  }
  if (filters.length === 0) {
    return [];
  }
  const [filter] = filters;
  const key = Array.isArray(filter.key) ? filter.key : [filter.key];
  const isIdFilter = key.length === 1 && key[0] === 'id' && (filter.operator ?? 'eq') === 'eq' && (filter.mode ?? 'or') === 'or';
  return isIdFilter ? filter.values.filter((value): value is string => typeof value === 'string') : null;
};

export const isFilterGroupJsonEmpty = (filters?: string | null): boolean => {
  if (!filters || filters.trim().length === 0) {
    return true;
  }
  try {
    const parsed = JSON.parse(filters) as StoredFilterGroup;
    return (parsed.filters ?? []).length === 0 && (parsed.filterGroups ?? []).length === 0;
  } catch {
    return true;
  }
};
// endregion

// region form
export interface HuntNativeQueryFormValue {
  platform: string;
  language: string;
  query: string;
  pipeline: string;
}

export interface HuntFormValues {
  name: string;
  description: string;
  hypothesis: string;
  hunt_type: HuntTypeValue;
  hunt_status: HuntStatusValue;
  sigma_rule: string;
  native_queries: HuntNativeQueryFormValue[];
  scopePlatforms: FieldOption[];
  schedule_mode: HuntScheduleMode;
  schedule_cron: string;
  hunt_pir_activation: boolean;
  time_window_hours: number | string;
  expected_observables: string[];
  benign_patterns: string;
  escalation_threshold: number | string;
  hunt_max_results: number | string;
  huntTargets: FieldOption[];
  huntTechniques: FieldOption[];
  huntSources: FieldOption[];
  createdBy: FieldOption | undefined | null;
  objectMarking: FieldOption[];
  objectLabel: FieldOption[];
  externalReferences: FieldOption[];
}

export const emptyHuntFormValues = (): HuntFormValues => ({
  name: '',
  description: '',
  hypothesis: '',
  hunt_type: 'telemetry',
  hunt_status: 'draft',
  sigma_rule: '',
  native_queries: [],
  scopePlatforms: [],
  schedule_mode: 'manual',
  schedule_cron: '',
  hunt_pir_activation: false,
  time_window_hours: HUNT_DEFAULT_TIME_WINDOW_HOURS,
  expected_observables: [],
  benign_patterns: '',
  escalation_threshold: HUNT_DEFAULT_ESCALATION_THRESHOLD,
  hunt_max_results: '',
  huntTargets: [],
  huntTechniques: [],
  huntSources: [],
  createdBy: undefined,
  objectMarking: [],
  objectLabel: [],
  externalReferences: [],
});

export const buildHuntSchedule = (mode: HuntScheduleMode, cron: string): string => {
  if (mode === 'standing') {
    return HUNT_SCHEDULE_STANDING;
  }
  if (mode === 'cron') {
    return cron.trim();
  }
  return HUNT_SCHEDULE_MANUAL;
};

/** Form fields of a stored schedule, the inverse of buildHuntSchedule. */
export const huntScheduleFormValues = (schedule?: string | null): { schedule_mode: HuntScheduleMode; schedule_cron: string } => {
  const mode = huntScheduleMode(schedule);
  return { schedule_mode: mode, schedule_cron: mode === 'cron' ? (schedule ?? '').trim() : '' };
};

/** One benign pattern per line, blank lines ignored, duplicates removed. */
export const parseBenignPatterns = (text: string): string[] => {
  return Array.from(new Set(text.split(/\r?\n/).map((line) => line.trim()).filter((line) => line.length > 0)));
};

export const normalizeNativeQueries = (rows: HuntNativeQueryFormValue[]) => {
  return rows
    .filter((row) => row.platform.trim().length > 0 && row.query.trim().length > 0)
    .map((row) => ({
      platform: row.platform.trim(),
      language: row.language.trim(),
      query: row.query,
      pipeline: row.pipeline.trim().length > 0 ? row.pipeline.trim() : null,
    }));
};

const toInteger = (value: number | string, fallback: number | null): number | null => {
  if (value === '' || value === null || value === undefined) {
    return fallback;
  }
  const numeric = Number(value);
  return Number.isFinite(numeric) ? Math.round(numeric) : fallback;
};

const optionValues = (options: FieldOption[]) => options.map(({ value }) => value);

/** Turns the creation form values into the HuntAddInput of the API. */
export const toHuntAddInput = (values: HuntFormValues, triggerFilters: string) => {
  const schedule = buildHuntSchedule(values.schedule_mode, values.schedule_cron);
  return {
    name: values.name.trim(),
    description: values.description,
    hypothesis: values.hypothesis,
    hunt_type: values.hunt_type,
    hunt_status: values.hunt_status,
    sigma_rule: values.hunt_type === 'telemetry' ? values.sigma_rule : '',
    native_queries: normalizeNativeQueries(values.native_queries),
    hunt_scope: values.hunt_type === 'telemetry' ? buildHuntScope(optionValues(values.scopePlatforms)) : '',
    hunt_schedule: schedule,
    trigger_filters: schedule === HUNT_SCHEDULE_STANDING ? triggerFilters : '',
    hunt_pir_activation: values.hunt_pir_activation,
    time_window_hours: toInteger(values.time_window_hours, HUNT_DEFAULT_TIME_WINDOW_HOURS),
    expected_observables: values.expected_observables,
    benign_patterns: parseBenignPatterns(values.benign_patterns),
    escalation_threshold: toInteger(values.escalation_threshold, HUNT_DEFAULT_ESCALATION_THRESHOLD),
    hunt_max_results: toInteger(values.hunt_max_results, null),
    huntTargets: optionValues(values.huntTargets),
    huntTechniques: optionValues(values.huntTechniques),
    huntSources: optionValues(values.huntSources),
    createdBy: values.createdBy?.value,
    objectMarking: optionValues(values.objectMarking),
    objectLabel: optionValues(values.objectLabel),
    externalReferences: optionValues(values.externalReferences),
  };
};

/** Attributes of the edition drawer; the status and the logic have their own controls. */
export const HUNT_EDITABLE_KEYS = [
  'name',
  'description',
  'hypothesis',
  'hunt_type',
  'hunt_scope',
  'hunt_schedule',
  'trigger_filters',
  'hunt_pir_activation',
  'time_window_hours',
  'expected_observables',
  'benign_patterns',
  'escalation_threshold',
  'hunt_max_results',
  'huntTargets',
  'huntTechniques',
  'huntSources',
  'createdBy',
  'objectMarking',
] as const;

const toEditValue = (value: unknown): unknown[] => {
  if (Array.isArray(value)) return value;
  if (value === null || value === undefined) return [];
  return [value];
};

/** Field patches turning the initial edition values into the submitted ones, changed attributes only. */
export const buildHuntEditPatch = (
  initial: HuntFormValues,
  initialTriggerFilters: string,
  values: HuntFormValues,
  triggerFilters: string,
): { key: string; value: unknown[] }[] => {
  const before = toHuntAddInput(initial, initialTriggerFilters) as Record<string, unknown>;
  const after = toHuntAddInput(values, triggerFilters) as Record<string, unknown>;
  return HUNT_EDITABLE_KEYS
    .filter((key) => JSON.stringify(before[key] ?? null) !== JSON.stringify(after[key] ?? null))
    .map((key) => ({ key, value: toEditValue(after[key]) }));
};
// endregion

// region prefill from an entity ("Hunt this")
export interface HuntPrefillEntity {
  id: string;
  entity_type: string;
  name: string;
}

export interface HuntPrefill {
  huntTargets: FieldOption[];
  huntTechniques: FieldOption[];
  huntSources: FieldOption[];
}

const toOption = (entity: HuntPrefillEntity): FieldOption => ({ value: entity.id, label: entity.name, type: entity.entity_type });

const uniqueOptions = (options: FieldOption[]) => Array.from(new Map(options.map((option) => [option.value, option])).values());

/**
 * Distributes entities into the hunt references: threats become targets, attack patterns
 * techniques, indicators and reports sources. Other types are ignored.
 */
export const buildHuntPrefill = (entities: HuntPrefillEntity[]): HuntPrefill => ({
  huntTargets: uniqueOptions(entities.filter((entity) => HUNT_TARGET_TYPES.includes(entity.entity_type)).map(toOption)),
  huntTechniques: uniqueOptions(entities.filter((entity) => HUNT_TECHNIQUE_TYPES.includes(entity.entity_type)).map(toOption)),
  huntSources: uniqueOptions(entities.filter((entity) => HUNT_SOURCE_TYPES.includes(entity.entity_type)).map(toOption)),
});

/** Default name of a hunt created from an entity page. */
export const buildHuntPrefillName = (entityName: string) => `Hunt - ${entityName}`.substring(0, 250);
// endregion

// region entity pages offering hunts
const HUNTABLE_ENTITY_PATHS: RegExp[] = [
  /^\/dashboard\/techniques\/attack_patterns\/[^/]+/,
  /^\/dashboard\/threats\/intrusion_sets\/[^/]+/,
  /^\/dashboard\/arsenal\/malwares\/[^/]+/,
  /^\/dashboard\/analyses\/reports\/[^/]+/,
  /^\/dashboard\/observations\/indicators\/[^/]+/,
  /^\/dashboard\/pirs\/[^/]+/,
];

/** Entity pages (Attack Pattern, Intrusion Set, Malware, Report, Indicator, PIR) where a hunt can be planned. */
export const isHuntableEntityPath = (pathname: string) => HUNTABLE_ENTITY_PATHS.some((pattern) => pattern.test(pathname));
// endregion

// region coverage
// Computed by the platform over every emulation run of the hunt (Hunt.techniqueValidations)
export type HuntTechniqueValidationStatus = 'validated' | 'not_detected' | 'in_progress' | 'not_validated';

export const huntTechniqueValidationLabel = (status: HuntTechniqueValidationStatus) => {
  switch (status) {
    case 'validated': return 'Detection proven';
    case 'not_detected': return 'Not detected';
    case 'in_progress': return 'Validation in progress';
    default: return 'Not validated';
  }
};

export const huntTechniqueValidationSeverity = (status: HuntTechniqueValidationStatus): ChipSeverity => {
  switch (status) {
    case 'validated': return 'low';
    case 'not_detected': return 'critical';
    case 'in_progress': return 'info';
    default: return 'neutral';
  }
};
// endregion
