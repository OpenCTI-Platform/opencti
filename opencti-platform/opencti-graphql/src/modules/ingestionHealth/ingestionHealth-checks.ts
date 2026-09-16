// Ingestion health — pure evaluation.
//
// NO I/O by design: the manager and the GraphQL resolver both call this, which
// is what stops the chip in the UI and the alert in an email ever disagreeing
// about the same source. Everything it needs arrives in
// `IngestionHealthInput`; everything it decides comes back in the result.
//
// Scope: liveness and productivity (MVP). `kind: 'runtime'` is the only check
// kind today — the discriminator exists so the configuration increment is
// additive rather than a refactor.

import {
  type CheckParams,
  type IngestionCheckCode,
  renderCheckMessage,
  sanitizeCheckDetail,
  STATUS_LABELS,
} from './ingestionHealth-messages';
import {
  DEFAULT_THRESHOLDS,
  type IngestionCheck,
  type IngestionCheckSeverity,
  type IngestionHealth,
  type IngestionHealthInput,
  type IngestionHealthObservation,
  type IngestionHealthStatus,
  type IngestionHealthThresholds,
} from './ingestionHealth-types';

// region rule profiles
//
// Applying one rule set to every source is the main false-positive generator:
// a demand-driven enrichment connector has no schedule, a run_and_terminate
// connector is *supposed* to be absent between runs, and a daily CSV with no
// new rows is not broken. The profile decides which checks may run at all.

export interface RuleProfile {
  heartbeat: boolean;
  queue: boolean;
  schedule: boolean;
  emptyRuns: boolean;
  cursor: boolean;
}

const DEMAND_DRIVEN_TYPES = ['INTERNAL_ENRICHMENT', 'INTERNAL_IMPORT_FILE', 'INTERNAL_EXPORT_FILE'];

export const resolveRuleProfile = (input: IngestionHealthInput): RuleProfile => {
  if (input.source_kind === 'feed') {
    // No per-run object count exists on a feed, so EMPTY_RUNS is not
    // observable; a stalled cursor carries that signal instead.
    return { heartbeat: false, queue: false, schedule: true, emptyRuns: false, cursor: true };
  }
  if (input.source_kind === 'sync') {
    return { heartbeat: false, queue: false, schedule: true, emptyRuns: false, cursor: true };
  }
  // connectors
  const isDemandDriven = DEMAND_DRIVEN_TYPES.includes(input.connector_type ?? '');
  if (isDemandDriven) {
    // Judged on its queue, never on the calendar: a connector with nothing to
    // do is healthy, one with work waiting and no consumer is broken.
    return {
      heartbeat: !input.run_and_terminate,
      queue: input.auto !== false,
      schedule: false,
      emptyRuns: false,
      cursor: false,
    };
  }
  if (input.connector_type === 'STREAM') {
    return { heartbeat: !input.run_and_terminate, queue: true, schedule: false, emptyRuns: false, cursor: true };
  }
  return {
    heartbeat: !input.run_and_terminate,
    queue: true,
    schedule: Boolean(input.next_expected_at || input.expected_period_seconds),
    emptyRuns: true,
    cursor: false,
  };
};

// endregion

// region checks

const secondsBetween = (a: Date, b: Date): number => Math.floor((a.getTime() - b.getTime()) / 1000);

const buildCheck = (
  code: IngestionCheckCode,
  severity: IngestionCheckSeverity,
  params: CheckParams,
  detail?: string,
): IngestionCheck => ({
  kind: 'runtime',
  code,
  severity,
  params,
  message: renderCheckMessage(code, params),
  detail: sanitizeCheckDetail(detail),
});

// Most diagnostic first. The head of this list becomes the summary headline,
// so a reboot loop or an error beats "it is late".
const CHECK_RANK: IngestionCheckCode[] = [
  'LAST_RUN_ERROR',
  'NO_HEARTBEAT',
  'NO_CONSUMER',
  'CURSOR_STALLED',
  'EMPTY_RUNS',
  'RUN_OVERDUE',
  'RUN_STALE',
  'NEVER_RUN',
  'MANUALLY_STOPPED',
];

const rankChecks = (checks: IngestionCheck[]): IngestionCheck[] => {
  return [...checks].sort((a, b) => CHECK_RANK.indexOf(a.code) - CHECK_RANK.indexOf(b.code));
};

// True when the source tells us when it intends to run. Connectors only reach
// the schedule checks at all when this holds; feeds and syncs are always
// schedule-checked, and an "auto" feed lands on the unscheduled branch.
const hasDeclaredSchedule = (input: IngestionHealthInput): boolean => {
  return Boolean(input.next_expected_at || (input.expected_period_seconds && input.expected_period_seconds > 0));
};

// The tolerance before a source counts as late. Expressed in *periods* for
// scheduled sources — two missed runs is 10 minutes for a 5-minute connector
// and two days for a daily feed. A source with no declared schedule gets a flat
// tolerance instead: the evaluation interval is far shorter than the manager's
// own run floor, so using it here reports healthy feeds as late.
export const computeOverdueToleranceSeconds = (
  input: IngestionHealthInput,
  thresholds: IngestionHealthThresholds,
): number => {
  const period = input.expected_period_seconds;
  if (period && period > 0) {
    return period * thresholds.missedPeriodsBeforeAlert;
  }
  return thresholds.unscheduledStaleSeconds;
};

export const computeIngestionChecks = (
  input: IngestionHealthInput,
  now: Date,
  thresholds: IngestionHealthThresholds = DEFAULT_THRESHOLDS,
): IngestionCheck[] => {
  // Deliberately stopped is a user action, not an incident: it short-circuits
  // everything so the UI never paints a switched-off source red.
  if (input.manually_stopped || !input.enabled) {
    return [buildCheck('MANUALLY_STOPPED', 'advisory', { since: input.last_seen_at?.toISOString() ?? '' })];
  }

  const profile = resolveRuleProfile(input);
  const checks: IngestionCheck[] = [];

  // -- liveness ------------------------------------------------------------
  if (profile.heartbeat) {
    const grace = (input.heartbeat_interval_seconds ?? thresholds.heartbeatGraceSeconds) * 2;
    if (!input.last_seen_at) {
      checks.push(buildCheck('NO_HEARTBEAT', 'blocking', { last_seen: '' }));
    } else if (secondsBetween(now, input.last_seen_at) > grace) {
      checks.push(buildCheck('NO_HEARTBEAT', 'blocking', { last_seen: input.last_seen_at.toISOString() }));
    }
  }

  if (profile.queue && input.queue) {
    const { messages_ready: waiting, consumers, idle_since: idleSince } = input.queue;
    // `consumers` is undefined when the broker was unreadable, which is not the
    // same as nothing listening — the strict === 0 keeps that case quiet.
    if (waiting > 0 && consumers === 0) {
      checks.push(buildCheck('NO_CONSUMER', 'blocking', { idle_since: idleSince?.toISOString() ?? '' }));
    }
  }

  // -- productivity --------------------------------------------------------
  if (input.last_run_failed) {
    checks.push(buildCheck('LAST_RUN_ERROR', 'blocking', { error: sanitizeCheckDetail(input.last_run_error) ?? 'unknown' }, input.last_run_error));
  }

  if (profile.schedule) {
    if (!input.last_run_at) {
      // A source that has never run is only suspicious once it is past due.
      const registeredFor = input.created_at ? secondsBetween(now, input.created_at) : 0;
      if (registeredFor > computeOverdueToleranceSeconds(input, thresholds)) {
        checks.push(buildCheck('NEVER_RUN', 'advisory', { since: input.created_at?.toISOString() ?? '' }));
      }
    } else if (hasDeclaredSchedule(input)) {
      const tolerance = computeOverdueToleranceSeconds(input, thresholds);
      const dueAt = input.next_expected_at ?? new Date(input.last_run_at.getTime() + (input.expected_period_seconds ?? 0) * 1000);
      if (secondsBetween(now, dueAt) > tolerance) {
        checks.push(buildCheck('RUN_OVERDUE', 'advisory', {
          expected_at: dueAt.toISOString(),
          last_run_at: input.last_run_at.toISOString(),
        }));
      }
    } else if (secondsBetween(now, input.last_run_at) > thresholds.unscheduledStaleSeconds) {
      // No declared schedule: there is no due date to quote, so report the
      // silence itself rather than inventing an expectation.
      checks.push(buildCheck('RUN_STALE', 'advisory', { last_run_at: input.last_run_at.toISOString() }));
    }
  }

  if (profile.emptyRuns) {
    const empties = input.consecutive_empty_runs ?? 0;
    // Weak signal on purpose: "returned nothing" is often legitimate, so it is
    // advisory and counted in runs rather than in elapsed time.
    if (empties >= thresholds.emptyRunsBeforeAlert) {
      checks.push(buildCheck('EMPTY_RUNS', 'advisory', { count: empties }));
    }
  }

  if (profile.cursor && input.cursor_hash && input.previous?.last_cursor_hash) {
    const stalled = input.cursor_hash === input.previous.last_cursor_hash;
    const empties = input.consecutive_empty_runs ?? 0;
    if (stalled && empties >= thresholds.emptyRunsBeforeAlert) {
      checks.push(buildCheck('CURSOR_STALLED', 'advisory', { since: input.previous.since }));
    }
  }

  return rankChecks(checks);
};

// endregion

// region fold

export const foldRuntimeStatus = (
  checks: IngestionCheck[],
  input: IngestionHealthInput,
  now: Date,
): IngestionHealthStatus => {
  if (checks.some((c) => c.code === 'MANUALLY_STOPPED')) {
    return 'stopped';
  }
  if (checks.some((c) => c.severity === 'blocking')) {
    return 'critical';
  }
  if (checks.length > 0) {
    return 'degraded';
  }
  // No complaints. Distinguish "working" from "not due yet" so a nightly feed
  // at 14:00 is not reported as a problem and not reported as fresh either.
  const profile = resolveRuleProfile(input);
  if (profile.schedule && input.next_expected_at && input.next_expected_at.getTime() > now.getTime()) {
    const period = input.expected_period_seconds ?? 0;
    const producedThisPeriod = input.last_productive_at
      && secondsBetween(now, input.last_productive_at) <= Math.max(period, 1);
    return producedThisPeriod ? 'healthy' : 'idle';
  }
  if (!input.last_seen_at && !input.last_run_at) {
    return 'unknown';
  }
  return 'healthy';
};

// endregion

export const buildSummary = (status: IngestionHealthStatus, checks: IngestionCheck[]): string => {
  const label = STATUS_LABELS[status] ?? status;
  const headline = checks[0];
  return headline ? `${label} — ${headline.message}` : label;
};

// region observation
//
// The counters that are only observable *across* evaluations. The manager owns
// the Redis read and write; the arithmetic lives here with the rest of the pure
// logic, because it is the other half of what EMPTY_RUNS and CURSOR_STALLED
// read back. Nothing else writes these — if this does not advance them, the
// cursor check can never fire.

type ProductivityCounters = Pick<
IngestionHealthObservation,
'last_run_at' | 'last_cursor_hash' | 'consecutive_empty_runs'
>;

export const advanceProductivityCounters = (
  input: IngestionHealthInput,
  previous: IngestionHealthObservation | null | undefined,
): ProductivityCounters => {
  const lastRunAt = input.last_run_at?.toISOString();

  // A connector counts empty runs from its works, which carry a real per-run
  // object count, so the input value is already authoritative.
  if (input.source_kind === 'connector') {
    return {
      last_run_at: lastRunAt,
      last_cursor_hash: input.cursor_hash ?? previous?.last_cursor_hash,
      consecutive_empty_runs: input.consecutive_empty_runs ?? 0,
    };
  }

  // Feeds and syncs have no per-run object count, so "ran and brought nothing
  // in" is only visible as a cursor that did not move between two runs. Counted
  // per run, never per evaluation — at a 60s cadence the latter would reach the
  // threshold in three minutes for a daily feed.
  const carried = previous?.consecutive_empty_runs ?? 0;
  const hasNewRun = Boolean(lastRunAt) && lastRunAt !== previous?.last_run_at;
  if (!hasNewRun) {
    return {
      last_run_at: previous?.last_run_at ?? lastRunAt,
      last_cursor_hash: previous?.last_cursor_hash ?? input.cursor_hash,
      consecutive_empty_runs: carried,
    };
  }
  const moved = input.cursor_hash !== undefined && input.cursor_hash !== previous?.last_cursor_hash;
  return {
    last_run_at: lastRunAt,
    last_cursor_hash: input.cursor_hash ?? previous?.last_cursor_hash,
    consecutive_empty_runs: moved ? 0 : carried + 1,
  };
};

// endregion

export const computeIngestionHealth = (
  input: IngestionHealthInput,
  now: Date,
  thresholds: IngestionHealthThresholds = DEFAULT_THRESHOLDS,
): IngestionHealth => {
  const checks = computeIngestionChecks(input, now, thresholds);
  const status = foldRuntimeStatus(checks, input, now);
  const changed = input.previous?.status !== status;
  return {
    status,
    summary: buildSummary(status, checks),
    checks,
    since: changed || !input.previous ? now : new Date(input.previous.since),
    last_productive_at: input.last_productive_at,
    next_expected_at: input.next_expected_at,
  };
};
