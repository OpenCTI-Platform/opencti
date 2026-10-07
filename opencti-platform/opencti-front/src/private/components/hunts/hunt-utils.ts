import type { ChipSeverity } from '@filigran/design-system';
import type { FieldOption } from '../../../utils/field';
import { HUNT_SCHEDULE_MANUAL, HUNT_SCHEDULE_STANDING, type HuntScheduleMode, huntScheduleMode } from './hunt-schedule-utils';
import { parseIocText } from './hunt-ioc-utils';

export const HUNT_ENTITY_TYPE = 'Hunt';
export const HUNT_RUN_ENTITY_TYPE = 'Hunt-Run';

export const HUNT_TYPES = ['indicators', 'telemetry', 'infrastructure'] as const;
export const HUNT_STATUSES = ['draft', 'active', 'paused', 'retired'] as const;
export const HUNT_SOURCE_KINDS = ['analyst', 'agent', 'hub'] as const;
export const HUNT_RUN_STATUSES = ['queued', 'running', 'completed', 'failed', 'timeout', 'cancelled'] as const;
export const HUNT_RUN_TRIGGERS = ['manual', 'schedule', 'standing', 'pir', 'playbook', 'emulation', 'preview', 'retry'] as const;
export const HUNT_RUN_VERDICTS = ['pending', 'true_positive', 'benign', 'inconclusive'] as const;
export const HUNT_ANALYST_VERDICTS = ['true_positive', 'benign', 'inconclusive'] as const;

export type HuntTypeValue = typeof HUNT_TYPES[number];
export type HuntStatusValue = typeof HUNT_STATUSES[number];
export type HuntSourceKindValue = typeof HUNT_SOURCE_KINDS[number];
export type HuntRunStatusValue = typeof HUNT_RUN_STATUSES[number];
export type HuntRunTriggerValue = typeof HUNT_RUN_TRIGGERS[number];
export type HuntRunVerdictValue = typeof HUNT_RUN_VERDICTS[number];

export const HUNT_PLATFORM_INTERNET = 'internet';

/**
 * Whether a hunt connector can run a translation preview of a hunt, as the dispatch picks connectors: the internet
 * platform for an infrastructure hunt, otherwise a security platform of the hunt scope, every one of them for an
 * unscoped hunt.
 */
export const isHuntPreviewConnector = (
  connector: { supports_preview?: boolean | null; supports_indicators?: boolean | null; platform?: string | null; securityPlatform?: { id: string } | null },
  huntType: string | null | undefined,
  scopePlatformIds: ReadonlyArray<string>,
) => {
  if (!connector.supports_preview) return false;
  if (huntType === 'infrastructure') return connector.platform === HUNT_PLATFORM_INTERNET;
  if (connector.platform === HUNT_PLATFORM_INTERNET || !connector.securityPlatform) return false;
  if (huntType === 'indicators' && !connector.supports_indicators) return false;
  return scopePlatformIds.length === 0 || scopePlatformIds.includes(connector.securityPlatform.id);
};

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

// Product and language names are proper nouns, only the internet entries are translated
const HUNT_PLATFORM_NAMES: Record<string, string> = {
  splunk: 'Splunk',
  'microsoft-sentinel': 'Microsoft Sentinel',
  'elastic-security': 'Elastic Security',
  'crowdstrike-logscale': 'CrowdStrike Falcon LogScale',
  'google-secops': 'Google SecOps',
  opensearch: 'OpenSearch',
  clickhouse: 'ClickHouse',
  's3-ocsf': 'Amazon S3 (OCSF)',
};
const HUNT_QUERY_LANGUAGE_NAMES: Record<string, string> = {
  spl: 'SPL',
  kql: 'KQL',
  esql: 'ES|QL',
  lucene: 'Lucene',
  eql: 'EQL',
  logscale: 'LogScale query language',
  'yara-l': 'YARA-L',
  udm: 'UDM search',
  ppl: 'PPL',
  'opensearch-lucene': 'OpenSearch Lucene',
  sql: 'SQL',
};

export const huntPlatformLabel = (platform: string | null | undefined, t_i18n: (key: string) => string) => {
  if (!platform) return '';
  if (platform === HUNT_PLATFORM_INTERNET) return t_i18n('Internet');
  return HUNT_PLATFORM_NAMES[platform] ?? platform;
};

export const huntQueryLanguageLabel = (language: string | null | undefined, t_i18n: (key: string) => string) => {
  if (!language) return '';
  if (language === 'internet') return t_i18n('Internet fingerprints');
  return HUNT_QUERY_LANGUAGE_NAMES[language] ?? language;
};

export const HUNT_TARGET_TYPES = ['Intrusion-Set', 'Malware', 'Campaign', 'Threat-Actor-Group', 'Threat-Actor-Individual'];
export const HUNT_TECHNIQUE_TYPES = ['Attack-Pattern'];
export const HUNT_SOURCE_TYPES = ['Indicator', 'Report'];
export const HUNT_SCOPE_TYPES = ['SecurityPlatform'];
/** Indicators and observables an indicator hunt looks for (the observable types a lookup can search). */
export const HUNT_IOC_ELEMENT_TYPES = ['Indicator', 'IPv4-Addr', 'IPv6-Addr', 'Domain-Name', 'Hostname', 'Url', 'Email-Addr', 'StixFile', 'Mac-Addr'];
/** Entities an indicator hunt takes its indicators and observables from. */
export const HUNT_IOC_ENTITY_TYPES = ['Report', 'Grouping', 'Case-Incident', 'Incident', ...HUNT_TARGET_TYPES, 'Tool'];
export const HUNT_TIME_WINDOW_PRESETS = [24, 168, 720] as const;

export const HUNT_DEFAULT_TIME_WINDOW_HOURS = 24;
export const HUNT_DEFAULT_ESCALATION_THRESHOLD = 10;
export const HUNT_MAX_ESCALATION_THRESHOLD = 1000000;
// The platform defaults of its configured limits, until the hunt configuration is loaded
export const HUNT_MAX_TIME_WINDOW_HOURS = 720;
export const HUNT_MAX_RESULTS_PER_RUN = 10000;
// Results a run reads when its hunt sets no limit (the platform default)
export const HUNT_DEFAULT_MAX_RESULTS = 1000;

/** The time window presets within the maximum of the platform, the maximum alone when it is under every preset. */
export const huntTimeWindowPresets = (maxHours: number): number[] => {
  const presets = HUNT_TIME_WINDOW_PRESETS.filter((hours) => hours <= maxHours);
  return presets.length > 0 ? presets : [maxHours];
};

type HuntTranslate = (message: string, options?: { values: Record<string, string | number> }) => string;

/** The ATT&CK techniques a Sigma rule tags that no attack pattern of the knowledge base matches: they link the hunt to nothing. */
export const huntUnresolvedTechniquesSentence = (techniques: ReadonlyArray<string>, t_i18n: HuntTranslate) => (techniques.length === 1
  ? t_i18n('1 tagged technique not found in the knowledge base: {techniques}. The hunt is not linked to it.', { values: { techniques: techniques[0] } })
  : t_i18n('{count} tagged techniques not found in the knowledge base: {techniques}. The hunt is not linked to them.', {
      values: { count: techniques.length, techniques: techniques.join(', ') },
    }));

/** The tagged techniques the knowledge base lacked when a run was created: the run gives them no coverage. */
export const huntRunUnresolvedTechniquesSentence = (techniques: ReadonlyArray<string>, t_i18n: HuntTranslate) => (techniques.length === 1
  ? t_i18n('1 tagged technique was not in the knowledge base when the run was created: {techniques}. The run gives it no coverage.', {
      values: { techniques: techniques[0] },
    })
  : t_i18n('{count} tagged techniques were not in the knowledge base when the run was created: {techniques}. The run gives them no coverage.', {
      values: { count: techniques.length, techniques: techniques.join(', ') },
    }));

/** A sentence of the platform in the language of the user: its English template is the translation key. */
export const huntMessageText = (
  message: { template: string; values: ReadonlyArray<{ name: string; value: string }> },
  t_i18n: HuntTranslate,
) => t_i18n(message.template, { values: Object.fromEntries(message.values.map(({ name, value }) => [name, value])) });

/** Why the hit count of a run with partial results is a lower bound: the result limit when the run reached it. */
export const huntRunPartialResultsSentence = (
  run: { hits_count?: number | null; maxResults?: number | null },
  platform: string,
  t_i18n: HuntTranslate,
  n: (value: number) => string,
) => {
  const hits = run.hits_count ?? 0;
  if (hits > 0 && hits >= (run.maxResults ?? HUNT_DEFAULT_MAX_RESULTS)) {
    return t_i18n('{platform} returned the first {count} results of this run, so the hit count is a lower bound.', { values: { platform, count: n(hits) } });
  }
  return t_i18n('{platform} returned partial results for this run, so the hit count is a lower bound.', { values: { platform } });
};

// Documentation of the hunting surfaces, linked from their help texts
const HUNT_DOCS_BASE = 'https://docs.opencti.io/latest/usage';
export const HUNT_DOCS = {
  hunts: `${HUNT_DOCS_BASE}/hunts/`,
  createHunt: `${HUNT_DOCS_BASE}/hunts/#create-a-hunt`,
  firstHunt: `${HUNT_DOCS_BASE}/your-first-hunt/`,
  indicatorHunts: `${HUNT_DOCS_BASE}/hunt-indicators/`,
  connectors: `${HUNT_DOCS_BASE}/hunt-connectors/`,
  connectionTest: `${HUNT_DOCS_BASE}/hunt-connectors/#test-the-connection`,
  runs: `${HUNT_DOCS_BASE}/hunts/#results-evidence-and-verdicts`,
  produces: `${HUNT_DOCS_BASE}/hunts/#what-a-run-produces`,
  runHunt: `${HUNT_DOCS_BASE}/hunts/#run-a-hunt`,
  activate: `${HUNT_DOCS_BASE}/hunts/#activate-a-hunt`,
  types: `${HUNT_DOCS_BASE}/hunts/#hunt-types`,
  indicatorSources: `${HUNT_DOCS_BASE}/hunt-indicators/#what-an-indicator-hunt-looks-for`,
  indicatorResults: `${HUNT_DOCS_BASE}/hunt-indicators/#results-and-verdicts`,
  automation: `${HUNT_DOCS_BASE}/hunt-automation/`,
  schedules: `${HUNT_DOCS_BASE}/hunt-automation/#schedules`,
  standing: `${HUNT_DOCS_BASE}/hunt-automation/#standing-hunts`,
  pir: `${HUNT_DOCS_BASE}/hunt-automation/#activation-by-priority-intelligence-requirements`,
  hitCounting: `${HUNT_DOCS_BASE}/hunts/#how-hits-are-counted`,
};

/**
 * The hits of a run with what is new in them: "120 (12 new, 108 seen before)". New and seen before cover the hits the
 * connector identified; when it returned more than it identified (partial results), the sentence says how many were
 * identified. Null for a run without hits or whose hits are not identified.
 */
export const huntRunHitsBreakdown = (
  run: { hits_count?: number | null; hits_new_count?: number | null; hits_recurring_count?: number | null; hits_identified?: boolean | null },
  t_i18n: HuntTranslate,
  n: (value: number) => string,
) => {
  const hits = run.hits_count ?? 0;
  if (hits === 0 || run.hits_identified !== true) {
    return null;
  }
  const fresh = run.hits_new_count ?? 0;
  const known = run.hits_recurring_count ?? 0;
  const values = { hits: n(hits), new: n(fresh), known: n(known), identified: n(fresh + known) };
  return fresh + known < hits
    ? t_i18n('{hits} ({new} new, {known} seen before, among {identified} identified)', { values })
    : t_i18n('{hits} ({new} new, {known} seen before)', { values });
};

/** The hits of the last run of a hunt, with the new ones when the platform knows them: "28 hits, 3 new". */
export const huntLastRunHits = (
  hunt: { last_hits_count?: number | null; last_new_hits_count?: number | null },
  t_i18n: HuntTranslate,
  n: (value: number) => string,
) => {
  const hits = hunt.last_hits_count ?? 0;
  const label = t_i18n('{count, plural, =0 {No hit} one {# hit} other {# hits}}', { values: { count: hits } });
  if (hits === 0 || hunt.last_new_hits_count === null || hunt.last_new_hits_count === undefined) {
    return label;
  }
  return t_i18n('{hits}, {new} new', { values: { hits: label, new: n(hunt.last_new_hits_count) } });
};

/** Whether a hunt runs by itself again and again (schedule, standing hunt, PIR activation): its runs search since the previous one. */
export const huntRunsRecur = (hunt: { hunt_schedule?: string | null; hunt_pir_activation?: boolean | null }) => {
  return huntScheduleMode(hunt.hunt_schedule) !== 'manual' || hunt.hunt_pir_activation === true;
};

/** Whether a sampled hit is new in its run, or since when and how often the runs of the hunt found it; null when unknown. */
export const huntHitRecurrence = (
  hit: { is_new?: boolean | null; times_seen?: number | null; known_since?: string | null },
  t_i18n: HuntTranslate,
  n: (value: number) => string,
  formatDate: (date: string) => string,
): { label: string; isNew: boolean } | null => {
  if (hit.is_new === true) {
    return { label: t_i18n('New'), isNew: true };
  }
  if (hit.is_new === false && hit.known_since) {
    const times = hit.times_seen ?? 1;
    return {
      label: times === 1
        ? t_i18n('Seen once since {date}', { values: { date: formatDate(hit.known_since) } })
        : t_i18n('Seen {count} times since {date}', { values: { count: n(times), date: formatDate(hit.known_since) } }),
      isNew: false,
    };
  }
  return null;
};

// The section of the hunt connectors page giving the account, permissions and configuration of each catalog connector
const HUNT_CONNECTOR_SETUP_SECTIONS: Record<string, string> = {
  'splunk-hunt': 'splunk',
  'microsoft-sentinel-hunt': 'microsoft-sentinel',
  'elastic-security-hunt': 'elastic-security',
  'crowdstrike-logscale-hunt': 'crowdstrike-logscale',
  'google-secops-hunt': 'google-secops',
  'opensearch-ocsf-hunt': 'opensearch-ocsf',
  'infrastructure-tracker': 'infrastructure-tracker',
};

export const huntConnectorSetupDocumentation = (slug: string | null | undefined) => {
  return `${HUNT_DOCS.connectors}#${HUNT_CONNECTOR_SETUP_SECTIONS[slug ?? ''] ?? 'before-you-start'}`;
};

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

export const huntTypeLabel = (huntType?: string | null) => {
  switch (huntType) {
    case 'indicators': return 'Indicators';
    case 'infrastructure': return 'Internet infrastructure (outside-in)';
    default: return 'Detection rule (Sigma or native query)';
  }
};

/** What a hunt of each type needs and where it runs, one sentence. */
export const huntTypeDescription = (huntType?: string | null) => {
  switch (huntType) {
    case 'indicators': return 'Needs indicators or observables (IP addresses, domains, URLs, hashes): looks them up in the telemetry of your security platforms, no query language needed.';
    case 'infrastructure': return 'Needs an internet fingerprint query (certificate, JARM, HTTP title), not a Sigma rule or indicators: searches internet scan data for the servers of a threat with the infrastructure tracker connector, never your telemetry.';
    default: return 'Needs a Sigma rule or a native query: runs it on the logs and events of your SIEM, EDR or data lake.';
  }
};

/** Whether the runs of a hunt type extract observables of the types the hunt names: an indicator hunt sights the values it looks up instead. */
export const huntExtractsObservables = (huntType?: string | null) => huntType !== 'indicators';

/** What a run of each hunt type records in the knowledge, in one line: the documentation details it. */
export const huntRunProducesDescription = (huntType?: string | null) => {
  switch (huntType) {
    case 'indicators': return 'A run records a sighting of each indicator or observable whose value it finds, and observed data of its hits.';
    case 'infrastructure': return 'A run turns the internet hosts it finds into infrastructure of the targeted threats, with observables and indicators.';
    default: return 'A run with hits records sightings of the techniques and indicators of the hunt, observables and observed data.';
  }
};

/** Observable types by their names, in the language of the user. */
export const huntObservableTypeNames = (types: ReadonlyArray<string>, t_i18n: (message: string) => string) => types
  .map((type) => t_i18n(`entity_${type}`))
  .join(', ');

/** The meaning of each status, one line each, as the hunt page explains them. */
export const HUNT_STATUS_MEANINGS: Record<HuntStatusValue, string> = {
  draft: 'The hunt is being written; it never runs.',
  active: 'The hunt runs: on its schedule, when a PIR flags one of its targets, or when you click Run now.',
  paused: 'The schedule and the triggers are stopped; Run now still works.',
  retired: 'Kept for the record; it never runs again until it is reopened as a draft.',
};

/** The same meanings for a user who can only view the hunt, who is not shown the controls they name. */
export const HUNT_STATUS_MEANINGS_READ_ONLY: Record<HuntStatusValue, string> = {
  ...HUNT_STATUS_MEANINGS,
  active: 'The hunt runs: on its schedule, when a PIR flags one of its targets, or when a user who can edit it runs it.',
  paused: 'The schedule and the triggers are stopped; a user who can edit the hunt can still run it.',
};

/** The readiness sentences of the platform that name a control, as a user who can only view the hunt reads them. */
export const HUNT_READINESS_READ_ONLY_TEMPLATES: Record<string, string> = {
  'Manual: it runs when you click Run now': 'Manual: it runs when a user who can edit the hunt runs it',
};

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
    case 'timeout': return 'Timed out';
    case 'cancelled': return 'Cancelled';
    default: return 'Unknown';
  }
};

// `critical` is reserved for the true positive verdict, a finding that calls for a response
export const huntRunStatusSeverity = (status?: string | null): ChipSeverity => {
  switch (status) {
    case 'running': return 'info';
    case 'completed': return 'low';
    case 'timeout': return 'high';
    case 'failed': return 'high';
    default: return 'neutral';
  }
};

export const huntRunTriggerLabel = (trigger?: string | null) => {
  switch (trigger) {
    case 'manual': return 'Manual';
    case 'schedule': return 'Scheduled';
    case 'standing': return 'Standing hunt';
    case 'pir': return 'PIR activation';
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

export const huntIncidentSeverityLabel = (severity?: string | null) => {
  switch (severity) {
    case 'low': return 'Low';
    case 'medium': return 'Medium';
    case 'high': return 'High';
    case 'critical': return 'Critical';
    default: return 'Unknown';
  }
};

export type HuntRunFailureKind = 'timeout' | 'translation' | 'access' | 'refused' | 'request' | 'other';

export interface HuntRunFailure {
  kind: HuntRunFailureKind;
  /** Seconds the connector waited, when its report states them */
  timeoutSeconds: number | null;
}

/**
 * Class of failure of a failed or timed out run. Hunt connectors built on the connectors SDK report a failure as
 * "<exception class>: <message>" (HuntTimeoutError, HuntTranslationError, HuntAccessDeniedError, HuntExecutionError,
 * HuntRequestError). An access denied failure carries the same sentence as the connection test of the connector.
 */
export const huntRunFailure = (status?: string | null, errorMessage?: string | null): HuntRunFailure | null => {
  if (status !== 'failed' && status !== 'timeout') {
    return null;
  }
  const message = (errorMessage ?? '').trim();
  const seconds = /within (\d+) seconds/.exec(message);
  if (status === 'timeout' || message.startsWith('HuntTimeoutError')) {
    return { kind: 'timeout', timeoutSeconds: seconds ? Number(seconds[1]) : null };
  }
  if (message.startsWith('HuntTranslationError')) {
    return { kind: 'translation', timeoutSeconds: null };
  }
  if (message.startsWith('HuntAccessDeniedError')) {
    return { kind: 'access', timeoutSeconds: null };
  }
  if (message.startsWith('HuntExecutionError')) {
    return { kind: 'refused', timeoutSeconds: null };
  }
  if (message.startsWith('HuntRequestError')) {
    return { kind: 'request', timeoutSeconds: null };
  }
  return { kind: 'other', timeoutSeconds: null };
};

export const huntVerdictSourceLabel = (source?: string | null) => {
  switch (source) {
    case 'auto': return 'Automatic';
    case 'agent': return 'AI agent';
    case 'analyst': return 'Analyst';
    default: return 'Not recorded';
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
  hunt_ioc_values?: ReadonlyArray<unknown> | null;
  hunt_ioc_filters?: string | null;
  huntSources?: ReadonlyArray<unknown> | null;
}) => {
  const nativeQueries = hunt.native_queries ?? [];
  if (hunt.hunt_type === 'infrastructure') {
    return nativeQueries.some((nativeQuery) => nativeQuery.platform === HUNT_PLATFORM_INTERNET);
  }
  if (hunt.hunt_type === 'indicators') {
    return (hunt.hunt_ioc_values ?? []).length > 0 || (hunt.huntSources ?? []).length > 0 || !isFilterGroupJsonEmpty(hunt.hunt_ioc_filters);
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
export const HUNT_RUN_TERMINAL_STATUSES: string[] = ['completed', 'failed', 'timeout', 'cancelled'];

export const isTerminalHuntRun = (status?: string | null) => HUNT_RUN_TERMINAL_STATUSES.includes(status ?? '');

export interface HuntRunCapabilityInput {
  hunt_run_status?: string | null;
  hunt_run_mode?: string | null;
}

export const canSetHuntRunVerdict = (run: HuntRunCapabilityInput) => run.hunt_run_mode !== 'preview' && run.hunt_run_status === 'completed';
// A true positive opens or continues an incident only for a run that has none yet, and the analyst may record it alone
export const huntVerdictOffersIncident = (verdict: string, run: { incident_id?: string | null }) => verdict === 'true_positive' && !run.incident_id;
// The platform never retries a cancelled run: its hunt or its hunt connector was deleted
export const canRetryHuntRun = (run: HuntRunCapabilityInput) => run.hunt_run_mode !== 'preview' && isTerminalHuntRun(run.hunt_run_status)
  && run.hunt_run_status !== 'cancelled';
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
  // Indicator hunts: the indicators and observables to look for, the entities to take them from, the pasted values
  iocElements: FieldOption[];
  iocEntities: FieldOption[];
  ioc_values_text: string;
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
  iocElements: [],
  iocEntities: [],
  ioc_values_text: '',
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
export const toHuntAddInput = (values: HuntFormValues, triggerFilters: string, iocFilters = '') => {
  const schedule = buildHuntSchedule(values.schedule_mode, values.schedule_cron);
  const isIndicators = values.hunt_type === 'indicators';
  const sources = isIndicators
    ? Array.from(new Map([...values.iocElements, ...values.iocEntities, ...values.huntSources].map((option) => [option.value, option])).values())
    : values.huntSources;
  return {
    name: values.name.trim(),
    description: values.description,
    hypothesis: values.hypothesis,
    hunt_type: values.hunt_type,
    hunt_status: values.hunt_status,
    sigma_rule: values.hunt_type === 'telemetry' ? values.sigma_rule : '',
    native_queries: isIndicators ? [] : normalizeNativeQueries(values.native_queries),
    ...(isIndicators ? { hunt_ioc_values: parseIocText(values.ioc_values_text).values, hunt_ioc_filters: iocFilters } : {}),
    hunt_scope: values.hunt_type !== 'infrastructure' ? buildHuntScope(optionValues(values.scopePlatforms)) : '',
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
    huntSources: optionValues(sources),
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
    // What an indicator hunt looks for is edited in its Logic tab, never by the edition drawer
    .filter((key) => key !== 'huntSources' || (initial.hunt_type !== 'indicators' && values.hunt_type !== 'indicators'))
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

// Containers and incidents a "Hunt this" turns into an indicator hunt over the indicators and observables they hold
const HUNT_IOC_CONTAINER_PREFILL_TYPES = ['Grouping', 'Case-Incident', 'Incident'];

/** Whether "Hunt this" opens an indicator hunt for the entity: a supported observable, a grouping, a case or an incident. */
export const isIocHuntEntity = (entityType: string) => (HUNT_IOC_ELEMENT_TYPES.includes(entityType) && entityType !== 'Indicator')
  || HUNT_IOC_CONTAINER_PREFILL_TYPES.includes(entityType);

/** Indicator hunt a supported observable, a grouping, a case or an incident turns into. */
export const buildIocHuntPrefill = (entity: HuntPrefillEntity): Partial<HuntFormValues> => {
  const option = toOption(entity);
  return HUNT_IOC_CONTAINER_PREFILL_TYPES.includes(entity.entity_type)
    ? { hunt_type: 'indicators', iocEntities: [option] }
    : { hunt_type: 'indicators', iocElements: [option] };
};

/** Default name of a hunt created from an entity page. */
export const buildHuntPrefillName = (entityName: string) => `Hunt - ${entityName}`.substring(0, 250);

// Platform a native query written in the indicator pattern language runs on
const INDICATOR_PATTERN_PLATFORMS: Record<string, string> = {
  spl: 'splunk',
  kql: 'microsoft-sentinel',
  eql: 'elastic-security',
  esql: 'elastic-security',
};

export interface HuntIndicatorPrefillEntity extends HuntPrefillEntity {
  pattern_type?: string | null;
  pattern?: string | null;
}

/**
 * Hunt an indicator turns into, from its pattern type: a STIX pattern is looked up as an indicator,
 * a Sigma pattern becomes the detection rule, a SPL, KQL or EQL pattern a native query. The indicator
 * stays a source of the hunt in every case.
 */
export const buildIndicatorHuntPrefill = (indicator: HuntIndicatorPrefillEntity): Partial<HuntFormValues> => {
  const option = toOption(indicator);
  const patternType = (indicator.pattern_type ?? '').toLowerCase();
  const pattern = indicator.pattern ?? '';
  if (patternType === 'stix') {
    return { hunt_type: 'indicators', iocElements: [option] };
  }
  if (patternType === 'sigma' && pattern.trim().length > 0) {
    return { hunt_type: 'telemetry', sigma_rule: pattern, huntSources: [option] };
  }
  const platform = INDICATOR_PATTERN_PLATFORMS[patternType];
  if (platform && pattern.trim().length > 0) {
    return {
      hunt_type: 'telemetry',
      native_queries: [{ platform, language: patternType, query: pattern, pipeline: '' }],
      huntSources: [option],
    };
  }
  return { huntSources: [option] };
};
// endregion

// region derived content ("Hunt this" from an entity, Query.huntDerivedContent)
export interface HuntDerivedEntity {
  id: string;
  entity_type: string;
  name: string;
}
export interface HuntDerivedSource extends HuntDerivedEntity {
  relation: string;
}
export interface HuntDerivedElement extends HuntDerivedEntity {
  value_types: ReadonlyArray<string>;
  source_ids: ReadonlyArray<string>;
}
export interface HuntDerivedTechnique extends HuntDerivedEntity {
  x_mitre_id?: string | null;
}
export interface HuntDerivedRule extends HuntDerivedEntity {
  pattern_type: string;
  pattern: string;
  technique_ids: ReadonlyArray<string>;
}
export interface HuntDerived {
  entity: HuntDerivedSource;
  suggested_type?: string | null;
  sources: ReadonlyArray<HuntDerivedSource>;
  targets: ReadonlyArray<HuntDerivedSource>;
  elements: ReadonlyArray<HuntDerivedElement>;
  elements_truncated: boolean;
  unsupported_count: number;
  techniques: ReadonlyArray<HuntDerivedTechnique>;
  rules: ReadonlyArray<HuntDerivedRule>;
}

/** Entities "Hunt this" derives the content of a hunt from (a PIR prefills its targets only). */
export const HUNT_DERIVABLE_TYPES = [
  ...HUNT_TARGET_TYPES,
  'Tool',
  ...HUNT_TECHNIQUE_TYPES,
  'Report',
  ...HUNT_IOC_CONTAINER_PREFILL_TYPES,
  ...HUNT_IOC_ELEMENT_TYPES,
];
// Techniques of a container prefilled as covered techniques, the others stay in the knowledge of the container
const DERIVED_TECHNIQUES_PREFILL_MAX = 50;

export const huntTechniqueName = (technique: { name: string; x_mitre_id?: string | null }) => (technique.x_mitre_id ? `${technique.x_mitre_id} ${technique.name}` : technique.name);

const derivedOption = (entity: HuntDerivedEntity): FieldOption => ({ value: entity.id, label: entity.name, type: entity.entity_type });

/** The indicators and observables the form looks up now: those of the selected sources, and those picked one by one. */
export const selectedDerivedElements = (derived: HuntDerived, values: Pick<HuntFormValues, 'iocEntities' | 'iocElements'>) => {
  const selected = new Set([...values.iocEntities, ...values.iocElements].map((option) => option.value));
  return derived.elements.filter((element) => selected.has(element.id) || element.source_ids.some((sourceId) => selected.has(sourceId)));
};

/** Indicators and observables of the sources, per observable type of their first value, the most frequent first. */
export const countDerivedValueTypes = (elements: ReadonlyArray<HuntDerivedElement>) => {
  const counts = new Map<string, number>();
  elements.forEach((element) => {
    const type = element.value_types[0];
    if (type) counts.set(type, (counts.get(type) ?? 0) + 1);
  });
  return Array.from(counts.entries())
    .map(([type, count]) => ({ type, count }))
    .sort((a, b) => b.count - a.count || a.type.localeCompare(b.type));
};

const HUNT_VALUE_TYPE_COUNTS: Record<string, string> = {
  'IPv4-Addr': '{count, plural, one {# IPv4 address} other {# IPv4 addresses}}',
  'IPv6-Addr': '{count, plural, one {# IPv6 address} other {# IPv6 addresses}}',
  'Domain-Name': '{count, plural, one {# domain} other {# domains}}',
  Hostname: '{count, plural, one {# host name} other {# host names}}',
  Url: '{count, plural, one {# URL} other {# URLs}}',
  'Email-Addr': '{count, plural, one {# email address} other {# email addresses}}',
  StixFile: '{count, plural, one {# file} other {# files}}',
  'Mac-Addr': '{count, plural, one {# MAC address} other {# MAC addresses}}',
};

/** "12 domains, 8 IPv4 addresses, 3 files" */
export const formatDerivedValueTypes = (elements: ReadonlyArray<HuntDerivedElement>, t_i18n: HuntTranslate) => countDerivedValueTypes(elements)
  .map(({ type, count }) => t_i18n(HUNT_VALUE_TYPE_COUNTS[type] ?? '{count, plural, one {# value} other {# values}}', { values: { count } }))
  .join(', ');

/** The form values a detection rule turns a hunt into: its Sigma rule or its native query, with the techniques it covers. */
export const derivedRuleValues = (rule: HuntDerivedRule, derived: HuntDerived): Partial<HuntFormValues> => {
  const huntTechniques = derived.techniques.filter((technique) => rule.technique_ids.includes(technique.id))
    .map((technique) => ({ value: technique.id, label: huntTechniqueName(technique), type: technique.entity_type }));
  const base: Partial<HuntFormValues> = { hunt_type: 'telemetry', huntSources: [derivedOption(rule)], huntTechniques };
  const platform = INDICATOR_PATTERN_PLATFORMS[rule.pattern_type];
  if (rule.pattern_type !== 'sigma' && platform) {
    return { ...base, sigma_rule: '', native_queries: [{ platform, language: rule.pattern_type, query: rule.pattern, pipeline: '' }] };
  }
  return { ...base, sigma_rule: rule.pattern, native_queries: [] };
};

/** The detection rule of the derived content the form runs now, if any. */
export const selectedDerivedRule = (derived: HuntDerived, values: Pick<HuntFormValues, 'hunt_type' | 'huntSources'>) => {
  if (values.hunt_type !== 'telemetry') return null;
  const sourceIds = values.huntSources.map((option) => option.value);
  return derived.rules.find((rule) => sourceIds.includes(rule.id)) ?? null;
};

/**
 * The hunt "Hunt this" opens from the derived content of the entity: an indicator hunt over the sources when indicators
 * were found, otherwise a detection-rule hunt running the rule covering the most techniques; an indicator keeps the hunt
 * its pattern type calls for, an observable is looked up itself.
 */
export const buildDerivedHuntPrefill = (entity: HuntIndicatorPrefillEntity, derived: HuntDerived): Partial<HuntFormValues> => {
  const name = buildHuntPrefillName(entity.name);
  const huntTargets = uniqueOptions(derived.targets.map(derivedOption));
  const techniqueOptions = derived.techniques.map((technique) => ({ value: technique.id, label: huntTechniqueName(technique), type: technique.entity_type }));
  if (entity.entity_type === 'Indicator') {
    return { name, huntTargets, huntTechniques: techniqueOptions, ...buildIndicatorHuntPrefill(entity) };
  }
  if (isIocHuntEntity(entity.entity_type) && !HUNT_IOC_CONTAINER_PREFILL_TYPES.includes(entity.entity_type)) {
    return { name, ...buildIocHuntPrefill(entity) };
  }
  const isContainer = entity.entity_type === 'Report' || HUNT_IOC_CONTAINER_PREFILL_TYPES.includes(entity.entity_type);
  const huntTechniques = HUNT_TECHNIQUE_TYPES.includes(entity.entity_type) || isContainer ? techniqueOptions.slice(0, DERIVED_TECHNIQUES_PREFILL_MAX) : [];
  if (derived.suggested_type === 'indicators') {
    return { name, huntTargets, huntTechniques, hunt_type: 'indicators', iocEntities: uniqueOptions(derived.sources.map(derivedOption)) };
  }
  if (derived.rules.length > 0) {
    const ruleValues = derivedRuleValues(derived.rules[0], derived);
    return { name, huntTargets, ...ruleValues, huntTechniques: uniqueOptions([...huntTechniques, ...(ruleValues.huntTechniques ?? [])]) };
  }
  return { name, huntTargets, huntTechniques, hunt_type: 'telemetry' };
};

interface HuntConnectorPlatform {
  platform?: string | null;
  supports_indicators?: boolean | null;
  securityPlatform?: { id: string } | null;
}

/** Security platforms a live hunt connector can run a hunt of the type on (an indicator hunt needs indicator lookups). */
export const countHuntPlatforms = (connectors: ReadonlyArray<HuntConnectorPlatform>, huntType: string) => new Set(connectors
  .filter((connector) => connector.platform !== HUNT_PLATFORM_INTERNET && !!connector.securityPlatform)
  .filter((connector) => huntType !== 'indicators' || !!connector.supports_indicators)
  .map((connector) => connector.securityPlatform?.id)).size;

export interface HuntSummaryInput {
  name: string;
  huntType: string;
  scopePlatforms: ReadonlyArray<FieldOption>;
  availablePlatforms: number;
  indicatorsCount: number;
  ruleName: string | null;
  hasLogic: boolean;
  timeWindowHours: number;
  escalationThreshold: number;
}

/** The time window of a run, in days from two whole days. */
export const formatHuntWindow = (hours: number, t_i18n: HuntTranslate) => (hours >= 48 && hours % 24 === 0
  ? t_i18n('{count, plural, one {# day} other {# days}}', { values: { count: hours / 24 } })
  : t_i18n('{count, plural, one {# hour} other {# hours}}', { values: { count: hours } }));

/**
 * What a hunt started from an entity does, in plain language, from the current form values: what it hunts, where, over
 * which period, and what a hit produces.
 */
export const buildHuntSummary = (input: HuntSummaryInput, t_i18n: HuntTranslate): string[] => {
  const name = input.name;
  if (input.huntType === 'infrastructure') {
    return [
      t_i18n('You are hunting the infrastructure of {name} on the internet: the hunt runs its fingerprint queries on internet scan data through the infrastructure tracker connector, never on your telemetry.', { values: { name } }),
      t_i18n('From {count, plural, one {# hit} other {# hits}}, a run proposes an incident.', { values: { count: input.escalationThreshold } }),
    ];
  }
  let platforms: string;
  if (input.scopePlatforms.length === 1) {
    platforms = String(input.scopePlatforms[0].label);
  } else if (input.scopePlatforms.length > 1 || input.availablePlatforms > 0) {
    const count = input.scopePlatforms.length > 1 ? input.scopePlatforms.length : input.availablePlatforms;
    platforms = t_i18n('{count, plural, one {# security platform} other {# security platforms}}', { values: { count } });
  } else {
    platforms = t_i18n('your security platforms (no hunt connector can run it yet)');
  }
  const window = formatHuntWindow(input.timeWindowHours, t_i18n);
  let what: string;
  if (input.huntType === 'indicators') {
    what = input.indicatorsCount > 0
      ? t_i18n('You are hunting {name} on {platforms}: the hunt searches your telemetry for its {count, plural, one {# known indicator} other {# known indicators}} over the last {window}.', { values: { name, platforms, window, count: input.indicatorsCount } })
      : t_i18n('You are hunting {name} on {platforms}: the hunt searches your telemetry for the indicators and observables you add below over the last {window}.', { values: { name, platforms, window } });
  } else if (input.ruleName) {
    what = t_i18n('You are hunting {name} on {platforms}: the hunt runs the detection rule "{rule}" on your telemetry over the last {window}.', { values: { name, platforms, window, rule: input.ruleName } });
  } else if (input.hasLogic) {
    what = t_i18n('You are hunting {name} on {platforms}: the hunt runs its Sigma rule or native queries on your telemetry over the last {window}.', { values: { name, platforms, window } });
  } else {
    what = t_i18n('You are hunting {name} on {platforms}: the hunt runs the Sigma rule or the native queries you write below on your telemetry over the last {window}.', { values: { name, platforms, window } });
  }
  return [
    what,
    t_i18n('A hit creates a sighting and, from {count, plural, one {# hit} other {# hits}}, proposes an incident.', { values: { count: input.escalationThreshold } }),
  ];
};
// endregion

// region entity pages offering hunts
const HUNTABLE_ENTITY_PATHS: RegExp[] = [
  /^\/dashboard\/techniques\/attack_patterns\/[^/]+/,
  /^\/dashboard\/threats\/intrusion_sets\/[^/]+/,
  /^\/dashboard\/arsenal\/malwares\/[^/]+/,
  /^\/dashboard\/analyses\/reports\/[^/]+/,
  /^\/dashboard\/observations\/indicators\/[^/]+/,
  /^\/dashboard\/analyses\/groupings\/[^/]+/,
  /^\/dashboard\/events\/incidents\/[^/]+/,
  /^\/dashboard\/cases\/incidents\/[^/]+/,
  /^\/dashboard\/pirs\/[^/]+/,
];

/** Entity pages (Attack Pattern, Intrusion Set, Malware, Report, Indicator, Grouping, Incident, Case-Incident, PIR) where a hunt can be planned. */
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
    case 'not_detected': return 'high';
    case 'in_progress': return 'info';
    default: return 'neutral';
  }
};
// endregion
