import type { BasicStoreEntity, StoreEntity } from '../../../types/store';
import type { StixInternal } from '../../../types/stix-2-1-common';

export const ENTITY_TYPE_HUNT_RUN = 'Hunt-Run';

// region enumerations
export const HUNT_RUN_STATUS_QUEUED = 'queued';
export const HUNT_RUN_STATUS_RUNNING = 'running';
export const HUNT_RUN_STATUS_COMPLETED = 'completed';
export const HUNT_RUN_STATUS_FAILED = 'failed';
export const HUNT_RUN_STATUS_TIMEOUT = 'timeout';
// The hunt or the hunt connector of the run was deleted before the run ended: it never ran, or its result has no hunt
export const HUNT_RUN_STATUS_CANCELLED = 'cancelled';
export const HUNT_RUN_STATUSES = [
  HUNT_RUN_STATUS_QUEUED,
  HUNT_RUN_STATUS_RUNNING,
  HUNT_RUN_STATUS_COMPLETED,
  HUNT_RUN_STATUS_FAILED,
  HUNT_RUN_STATUS_TIMEOUT,
  HUNT_RUN_STATUS_CANCELLED,
];
export const HUNT_RUN_ACTIVE_STATUSES = [HUNT_RUN_STATUS_QUEUED, HUNT_RUN_STATUS_RUNNING];
export const HUNT_RUN_TERMINAL_STATUSES = [HUNT_RUN_STATUS_COMPLETED, HUNT_RUN_STATUS_FAILED, HUNT_RUN_STATUS_TIMEOUT, HUNT_RUN_STATUS_CANCELLED];
// Terminated runs that get a finalization (statistics, incident, automatic verdict): a cancelled run gets none
export const HUNT_RUN_FINALIZABLE_STATUSES = [HUNT_RUN_STATUS_COMPLETED, HUNT_RUN_STATUS_FAILED, HUNT_RUN_STATUS_TIMEOUT];

export const HUNT_RUN_TRIGGER_MANUAL = 'manual';
export const HUNT_RUN_TRIGGER_SCHEDULE = 'schedule';
export const HUNT_RUN_TRIGGER_STANDING = 'standing';
export const HUNT_RUN_TRIGGER_PIR = 'pir';
export const HUNT_RUN_TRIGGER_PLAYBOOK = 'playbook';
export const HUNT_RUN_TRIGGER_EMULATION = 'emulation';
export const HUNT_RUN_TRIGGER_PREVIEW = 'preview';
export const HUNT_RUN_TRIGGER_RETRY = 'retry';
export const HUNT_RUN_TRIGGERS = [
  HUNT_RUN_TRIGGER_MANUAL,
  HUNT_RUN_TRIGGER_SCHEDULE,
  HUNT_RUN_TRIGGER_STANDING,
  HUNT_RUN_TRIGGER_PIR,
  HUNT_RUN_TRIGGER_PLAYBOOK,
  HUNT_RUN_TRIGGER_EMULATION,
  HUNT_RUN_TRIGGER_PREVIEW,
  HUNT_RUN_TRIGGER_RETRY,
];
// Triggers started without a human action, counted as autonomous runs.
export const HUNT_RUN_AUTONOMOUS_TRIGGERS = [HUNT_RUN_TRIGGER_SCHEDULE, HUNT_RUN_TRIGGER_STANDING, HUNT_RUN_TRIGGER_PIR, HUNT_RUN_TRIGGER_PLAYBOOK, HUNT_RUN_TRIGGER_EMULATION];
// Recurring runs of a hunt: each one searches from where the previous completed run of the hunt on the same security
// platform ended (minus the lookback overlap), never more than the time window of the hunt
export const HUNT_RUN_INCREMENTAL_TRIGGERS = [HUNT_RUN_TRIGGER_SCHEDULE, HUNT_RUN_TRIGGER_STANDING, HUNT_RUN_TRIGGER_PIR];

export const HUNT_RUN_MODE_EXECUTE = 'execute';
export const HUNT_RUN_MODE_PREVIEW = 'preview';
export const HUNT_RUN_MODES = [HUNT_RUN_MODE_EXECUTE, HUNT_RUN_MODE_PREVIEW];

export const HUNT_VERDICT_PENDING = 'pending';
export const HUNT_VERDICT_TRUE_POSITIVE = 'true_positive';
export const HUNT_VERDICT_BENIGN = 'benign';
export const HUNT_VERDICT_INCONCLUSIVE = 'inconclusive';
export const HUNT_VERDICTS = [HUNT_VERDICT_PENDING, HUNT_VERDICT_TRUE_POSITIVE, HUNT_VERDICT_BENIGN, HUNT_VERDICT_INCONCLUSIVE];

export const HUNT_VERDICT_SOURCE_AUTO = 'auto';
export const HUNT_VERDICT_SOURCE_ANALYST = 'analyst';
export const HUNT_VERDICT_SOURCE_AGENT = 'agent';
export const HUNT_VERDICT_SOURCES = [HUNT_VERDICT_SOURCE_AUTO, HUNT_VERDICT_SOURCE_ANALYST, HUNT_VERDICT_SOURCE_AGENT];
// endregion

// Kind of a telemetry hit in the program-wide evidence shape (url | document | tool_result | opencti_object)
export const HUNT_EVIDENCE_KIND_TOOL_RESULT = 'tool_result';

export interface HuntEvidence {
  field: string;
  value_hash: string;
  value_preview?: string | null;
  count: number;
  // The value is one the hunt logic matched (the connector says so, or a hit of the run matched it), not context of the event
  matched?: boolean;
}

export interface HuntHitField {
  field: string;
  value_hash: string;
  value_preview: string | null;
  // The preview is the whole value the connector hashed, neither truncated nor masked
  value_complete: boolean;
}

/** One event a run matched, as the platform stores it. */
export interface HuntHit {
  // Stable key of the hit (huntHitKey), computed over the hit as the connector reported it; absent on older runs
  hit_key?: string | null;
  event_id: string | null;
  timestamp: string | null;
  // The detection of the platform grouping the event (YARA-L): the events of one detection are one hit
  detection: string | null;
  matched: HuntHitField[];
  host: string | null;
  user: string | null;
  process: string | null;
}

// Connection test of a hunt connector: a message of this mode, answered by the connector with one result per check
export const HUNT_CONNECTION_CHECK_MODE = 'check';
export const HUNT_CONNECTION_CHECK_PENDING = 'pending';
export const HUNT_CONNECTION_CHECK_PASSED = 'passed';
export const HUNT_CONNECTION_CHECK_FAILED = 'failed';

// Verdict of one value of an indicator hunt run
export const HUNT_IOC_VERDICT_PENDING = 'pending';
export const HUNT_IOC_VERDICT_SEEN = 'seen';
export const HUNT_IOC_VERDICT_NOT_SEEN = 'not_seen';
export const HUNT_IOC_VERDICT_NOT_SEARCHED = 'not_searched';
export const HUNT_IOC_VERDICTS = [HUNT_IOC_VERDICT_PENDING, HUNT_IOC_VERDICT_SEEN, HUNT_IOC_VERDICT_NOT_SEEN, HUNT_IOC_VERDICT_NOT_SEARCHED];
export const HUNT_IOC_HOSTS_MAX = 10;

/** One value an indicator hunt run looked up, and what the platform reported for it. */
export interface HuntIocResult {
  key: string;
  observable_type: string;
  hash_algorithm?: string | null;
  value: string;
  // Internal ids of the indicators and observables the value comes from, none for a pasted value
  source_ids: string[];
  verdict: string;
  hits_count: number;
  first_seen?: string | null;
  last_seen?: string | null;
  hosts: string[];
  reason?: string | null;
  // Deployments of the source indicators on the security platform of the run (dissemination assurance)
  deployment_ids?: string[];
}

interface HuntRunAttributes {
  hunt_id: string;
  // The hunt of the run no longer exists (deleted, in the trash): the statistics leave the run out
  hunt_orphaned?: boolean | null;
  hunt_run_status: string;
  hunt_run_trigger: string;
  hunt_run_mode: string;
  security_platform_id?: string | null;
  connector_id?: string | null;
  connector_name?: string | null;
  work_id?: string | null;
  time_window_start?: string;
  time_window_end?: string;
  translated_query?: string | null;
  query_language?: string | null;
  ioc_results?: HuntIocResult[] | null;
  hits_count?: number | null;
  // Hits never seen before for the hunt on the security platform of the run, and hits already known (Hunt-Hit-Record).
  // A run whose connector identifies no hit (hits_identified false) counts every hit as new
  hits_new_count?: number | null;
  hits_recurring_count?: number | null;
  hits_identified?: boolean | null;
  // The completed run whose time window this autonomous run continues (incremental windows), null for a full window
  continues_run_id?: string | null;
  // Sightings of the hunt the run created; the others it found were updated in place
  sightings_created_count?: number | null;
  // The run added its hits to an incident still open from a previous run instead of opening a new one
  incident_continued?: boolean | null;
  // The platform returned partial results: hits_count is a lower bound
  results_truncated?: boolean | null;
  distinct_entities?: number | null;
  evidence_sample?: HuntEvidence[];
  hits_sample?: HuntHit[];
  first_hit_at?: string | null;
  last_hit_at?: string | null;
  hit_observation_ids?: string[];
  result_ids?: string[];
  verdict: string;
  verdict_source?: string | null;
  verdict_rationale?: string | null;
  hunt_analyst_feedback?: string | null;
  verdict_proposal?: string | null;
  verdict_proposal_confidence?: number | null;
  verdict_proposal_rationale?: string | null;
  verdict_proposal_agent?: string | null;
  incident_proposal?: string | null;
  incident_id?: string | null;
  draft_id?: string | null;
  aev_inject_id?: string | null;
  security_coverage_id?: string | null;
  technique_id?: string | null;
  triggered_by?: string | null;
  attempt: number;
  // The run this one retries (attempt - 1), set on every retry
  retry_of?: string | null;
  next_retry_at?: string | null;
  dispatched_at?: string | null;
  published_at?: string | null;
  started_at?: string | null;
  completed_at?: string | null;
  cost_ms?: number | null;
  error_message?: string | null;
  // False for a failure the same run meets again in the same way (translation, a query the platform rejects): no retry
  failure_retryable?: boolean | null;
  // The hunt logic the run was created from (huntLogicFingerprint): the translation of this logic is known from its runs
  hunt_logic_fingerprint?: string | null;
  // The run opens an incident draft by itself above the escalation threshold (autonomous runs, manual runs on opt-in)
  auto_escalation?: boolean | null;
  // ATT&CK techniques tagged in the Sigma rule that matched no attack pattern of the knowledge base at the creation
  unresolved_techniques?: string[];
  playbook_id?: string | null;
  playbook_execution_id?: string | null;
  playbook_step_id?: string | null;
  // The entity whose event started the playbook execution
  playbook_instance_id?: string | null;
  playbook_leader?: boolean | null;
  playbook_context?: string | null;
  playbook_resumed_at?: string | null;
  evidence_sources?: string[];
  last_evidence_at?: string | null;
}

/**
 * Continuation of a playbook waiting for hunt runs (PLAYBOOK_HUNT_COMPONENT), stored on the first run of the group
 * and replayed through the playbook step execution once every run of the group is terminated.
 */
export interface HuntPlaybookContext {
  playbook_id: string;
  step_id: string;
  previous_step_id: string;
  execution_id: string;
  event_id: string;
  data_instance_id: string;
  execution_start: string;
  include_results: boolean;
  bundle: string;
  previous_bundle: string;
}

export interface BasicStoreEntityHuntRun extends BasicStoreEntity, HuntRunAttributes {}

export interface StoreEntityHuntRun extends StoreEntity, HuntRunAttributes {}

export interface StixHuntRun extends StixInternal {
  hunt_id: string;
  hunt_run_status: string;
  hunt_run_trigger: string;
  verdict: string;
}
