/**
 * States of the runs, steps and deployments that timeline events come from. The timeline only carries the raw state:
 * each family the back end emits reads through the vocabulary of its owner below, and an unknown state shows nothing
 * rather than a raw value. The `hunt_run`, `deployment` and `investigation_run` families are only emitted when the
 * hunts, the indicator deployments and Case Autopilot are installed on the platform (soft checks on their types).
 */

export type TimelineStateSeverity = 'neutral' | 'info' | 'low' | 'medium' | 'high' | 'critical';

export interface TimelineSourceStateValue {
  readonly family: string;
  readonly state?: string | null;
  readonly verdict?: string | null;
  readonly validation?: string | null;
  readonly run_id?: string | null;
  readonly step?: string | null;
}

export interface TimelineStateChip {
  // Translation key of the label
  label: string;
  severity: TimelineStateSeverity;
  dimmed?: boolean;
}

type TimelineSourceStateResolver = (state: TimelineSourceStateValue) => TimelineStateChip | null;

export type InvestigationStepState = 'planned' | 'querying' | 'found' | 'nothing_found' | 'partial' | 'failed' | 'not_reached';

// The seven step states of the program, with their fixed labels and tones
export const INVESTIGATION_STEP_STATES: Record<InvestigationStepState, TimelineStateChip> = {
  planned: { label: 'Planned step', severity: 'neutral' },
  querying: { label: 'Querying', severity: 'info' },
  found: { label: 'Found', severity: 'low' },
  nothing_found: { label: 'Nothing found', severity: 'neutral' },
  partial: { label: 'Partial', severity: 'medium' },
  failed: { label: 'Failed', severity: 'high' },
  not_reached: { label: 'Not reached', severity: 'neutral', dimmed: true },
};

// States of the investigation engine and of the former run ledger, by step state
const ENGINE_STEP_STATES: Record<string, InvestigationStepState> = {
  planned: 'planned',
  pending: 'planned',
  queued: 'planned',
  running: 'querying',
  querying: 'querying',
  in_progress: 'querying',
  completed: 'found',
  succeeded: 'found',
  empty: 'nothing_found',
  no_result: 'nothing_found',
  degraded: 'partial',
  partial: 'partial',
  error: 'failed',
  failed: 'failed',
  timeout: 'failed',
  skipped: 'not_reached',
  cancelled: 'not_reached',
};

// Case-insensitive, and only the values of the map itself (never an inherited property such as `constructor`)
const lookup = <T>(map: Record<string, T>, value: string | null | undefined): T | null => {
  const key = value?.toLowerCase();
  return key && Object.prototype.hasOwnProperty.call(map, key) ? map[key] : null;
};

export const toInvestigationStepState = (state: string | null | undefined): InvestigationStepState | null => {
  return lookup(ENGINE_STEP_STATES, state);
};

type TimelineRunState = 'queued' | 'running' | 'completed' | 'partial' | 'failed' | 'timed_out' | 'cancelled';

// Lifecycle of a hunt run or an investigation run
const TIMELINE_RUN_STATES: Record<TimelineRunState, TimelineStateChip> = {
  queued: { label: 'Queued', severity: 'neutral' },
  running: { label: 'Running', severity: 'info' },
  completed: { label: 'Completed', severity: 'low' },
  partial: { label: 'Partial', severity: 'medium' },
  failed: { label: 'Failed', severity: 'high' },
  timed_out: { label: 'Timed out', severity: 'high' },
  cancelled: { label: 'Cancelled', severity: 'neutral', dimmed: true },
};

// States stored by the hunts and the investigation engine, by run state
const RUN_STATES: Record<string, TimelineRunState> = {
  planned: 'queued',
  pending: 'queued',
  queued: 'queued',
  running: 'running',
  querying: 'running',
  in_progress: 'running',
  completed: 'completed',
  succeeded: 'completed',
  degraded: 'partial',
  partial: 'partial',
  error: 'failed',
  failed: 'failed',
  timeout: 'timed_out',
  skipped: 'cancelled',
  cancelled: 'cancelled',
};

const runStateChip = (state: string | null | undefined): TimelineStateChip | null => {
  const runState = lookup(RUN_STATES, state);
  return runState ? TIMELINE_RUN_STATES[runState] : null;
};

// A decided verdict says more about a hunt run than the end of the run
const HUNT_VERDICTS: Record<string, TimelineStateChip> = {
  true_positive: { label: 'True positive', severity: 'high' },
  benign: { label: 'Benign', severity: 'low' },
  inconclusive: { label: 'Inconclusive', severity: 'medium' },
};

// A validation result says more about a deployment than its status
const DEPLOYMENT_VALIDATIONS: Record<string, TimelineStateChip> = {
  detected: { label: 'Detected', severity: 'low' },
  prevented: { label: 'Prevented', severity: 'low' },
  missed: { label: 'Missed', severity: 'high' },
  error: { label: 'Validation error', severity: 'medium' },
};

const DEPLOYMENT_STATUSES: Record<string, TimelineStateChip> = {
  pending: { label: 'Pending', severity: 'neutral' },
  deployed: { label: 'Deployed', severity: 'low' },
  active: { label: 'Active', severity: 'low' },
  failed: { label: 'Failed', severity: 'high' },
  removed: { label: 'Removed', severity: 'neutral', dimmed: true },
  expired: { label: 'Expired', severity: 'neutral', dimmed: true },
};

const TIMELINE_SOURCE_STATE_RESOLVERS: Record<string, TimelineSourceStateResolver> = {
  investigation_step: ({ state }) => {
    const step = toInvestigationStepState(state);
    return step ? INVESTIGATION_STEP_STATES[step] : null;
  },
  investigation_run: ({ state }) => runStateChip(state),
  hunt_run: ({ state, verdict }) => lookup(HUNT_VERDICTS, verdict) ?? runStateChip(state),
  deployment: ({ state, validation }) => lookup(DEPLOYMENT_VALIDATIONS, validation) ?? lookup(DEPLOYMENT_STATUSES, state),
};

export const resolveTimelineSourceState = (state: TimelineSourceStateValue | null | undefined): TimelineStateChip | null => {
  if (!state) return null;
  return TIMELINE_SOURCE_STATE_RESOLVERS[state.family]?.(state) ?? null;
};
