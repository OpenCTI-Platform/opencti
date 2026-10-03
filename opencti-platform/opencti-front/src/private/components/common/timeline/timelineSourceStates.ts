/**
 * States of the runs, steps and deployments that timeline events come from. The timeline only carries the raw state:
 * each family reads through the vocabulary of its owner, registered below, and an unknown state shows nothing rather
 * than a raw value. Owners add their family here: hunt runs (`hunt_run`, verdict chips of the hunts), deployments
 * (`deployment`, deployment states of the indicators) and Case Autopilot runs (`investigation_run`, run states).
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

export const toInvestigationStepState = (state: string | null | undefined): InvestigationStepState | null => {
  return state ? ENGINE_STEP_STATES[state.toLowerCase()] ?? null : null;
};

const TIMELINE_SOURCE_STATE_RESOLVERS: Record<string, TimelineSourceStateResolver> = {
  investigation_step: ({ state }) => {
    const step = toInvestigationStepState(state);
    return step ? INVESTIGATION_STEP_STATES[step] : null;
  },
};

export const resolveTimelineSourceState = (state: TimelineSourceStateValue | null | undefined): TimelineStateChip | null => {
  if (!state) return null;
  return TIMELINE_SOURCE_STATE_RESOLVERS[state.family]?.(state) ?? null;
};
