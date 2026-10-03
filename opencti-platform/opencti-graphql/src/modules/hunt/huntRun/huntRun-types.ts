import type { BasicStoreEntity, StoreEntity } from '../../../types/store';
import type { StixInternal } from '../../../types/stix-2-1-common';

export const ENTITY_TYPE_HUNT_RUN = 'Hunt-Run';

// region enumerations
export const HUNT_RUN_STATUS_QUEUED = 'queued';
export const HUNT_RUN_STATUS_RUNNING = 'running';
export const HUNT_RUN_STATUS_COMPLETED = 'completed';
export const HUNT_RUN_STATUS_FAILED = 'failed';
export const HUNT_RUN_STATUS_TIMEOUT = 'timeout';
export const HUNT_RUN_STATUSES = [HUNT_RUN_STATUS_QUEUED, HUNT_RUN_STATUS_RUNNING, HUNT_RUN_STATUS_COMPLETED, HUNT_RUN_STATUS_FAILED, HUNT_RUN_STATUS_TIMEOUT];
export const HUNT_RUN_ACTIVE_STATUSES = [HUNT_RUN_STATUS_QUEUED, HUNT_RUN_STATUS_RUNNING];
export const HUNT_RUN_TERMINAL_STATUSES = [HUNT_RUN_STATUS_COMPLETED, HUNT_RUN_STATUS_FAILED, HUNT_RUN_STATUS_TIMEOUT];

export const HUNT_RUN_TRIGGER_MANUAL = 'manual';
export const HUNT_RUN_TRIGGER_SCHEDULE = 'schedule';
export const HUNT_RUN_TRIGGER_STANDING = 'standing';
export const HUNT_RUN_TRIGGER_PLAYBOOK = 'playbook';
export const HUNT_RUN_TRIGGER_EMULATION = 'emulation';
export const HUNT_RUN_TRIGGER_PREVIEW = 'preview';
export const HUNT_RUN_TRIGGER_RETRY = 'retry';
export const HUNT_RUN_TRIGGERS = [
  HUNT_RUN_TRIGGER_MANUAL,
  HUNT_RUN_TRIGGER_SCHEDULE,
  HUNT_RUN_TRIGGER_STANDING,
  HUNT_RUN_TRIGGER_PLAYBOOK,
  HUNT_RUN_TRIGGER_EMULATION,
  HUNT_RUN_TRIGGER_PREVIEW,
  HUNT_RUN_TRIGGER_RETRY,
];
// Triggers started without a human action, counted as autonomous runs.
export const HUNT_RUN_AUTONOMOUS_TRIGGERS = [HUNT_RUN_TRIGGER_SCHEDULE, HUNT_RUN_TRIGGER_STANDING, HUNT_RUN_TRIGGER_PLAYBOOK, HUNT_RUN_TRIGGER_EMULATION];

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

export interface HuntEvidence {
  field: string;
  value_hash: string;
  value_preview?: string | null;
  count: number;
}

interface HuntRunAttributes {
  hunt_id: string;
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
  hits_count?: number | null;
  distinct_entities?: number | null;
  evidence_sample?: HuntEvidence[];
  result_ids?: string[];
  verdict: string;
  verdict_source?: string | null;
  verdict_rationale?: string | null;
  analyst_feedback?: string | null;
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
  next_retry_at?: string | null;
  dispatched_at?: string | null;
  started_at?: string | null;
  completed_at?: string | null;
  cost_ms?: number | null;
  error_message?: string | null;
}

export interface BasicStoreEntityHuntRun extends BasicStoreEntity, HuntRunAttributes {}

export interface StoreEntityHuntRun extends StoreEntity, HuntRunAttributes {}

export interface StixHuntRun extends StixInternal {
  hunt_id: string;
  hunt_run_status: string;
  hunt_run_trigger: string;
  verdict: string;
}
