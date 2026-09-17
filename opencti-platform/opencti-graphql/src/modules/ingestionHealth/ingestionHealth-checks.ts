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
  type IngestionCheckKind,
  type IngestionCheckSeverity,
  type IngestionConfigurationStatus,
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
  // Stability has exactly one data source, xtm-composer, which supervises
  // connector processes and nothing else. Feeds and synchronizers have no
  // process to supervise, so the axis does not apply to them at all.
  stability: boolean;
}

const DEMAND_DRIVEN_TYPES = ['INTERNAL_ENRICHMENT', 'INTERNAL_IMPORT_FILE', 'INTERNAL_EXPORT_FILE'];

export const resolveRuleProfile = (input: IngestionHealthInput): RuleProfile => {
  if (input.source_kind === 'feed') {
    // No per-run object count exists on a feed, so EMPTY_RUNS is not
    // observable; a stalled cursor carries that signal instead.
    return { heartbeat: false, queue: false, schedule: true, emptyRuns: false, cursor: true, stability: false };
  }
  if (input.source_kind === 'sync') {
    return { heartbeat: false, queue: false, schedule: true, emptyRuns: false, cursor: true, stability: false };
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
      stability: true,
    };
  }
  if (input.connector_type === 'STREAM') {
    return { heartbeat: !input.run_and_terminate, queue: true, schedule: false, emptyRuns: false, cursor: true, stability: true };
  }
  return {
    heartbeat: !input.run_and_terminate,
    queue: true,
    schedule: Boolean(input.next_expected_at || input.expected_period_seconds),
    emptyRuns: true,
    cursor: false,
    stability: true,
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
  kind: IngestionCheckKind = 'runtime',
): IngestionCheck => ({
  kind,
  code,
  severity,
  params,
  message: renderCheckMessage(code, params),
  detail: sanitizeCheckDetail(detail),
});

const buildConfigurationCheck = (
  code: IngestionCheckCode,
  severity: IngestionCheckSeverity,
  params: CheckParams = {},
  detail?: string,
): IngestionCheck => buildCheck(code, severity, params, detail, 'configuration');

// Most diagnostic first. The head of this list becomes the summary headline,
// so a reboot loop or an error beats "it is late".
const CHECK_RANK: IngestionCheckCode[] = [
  'LAST_RUN_ERROR',
  // A reboot loop explains more than the missing heartbeat it causes, so it
  // takes the headline off NO_HEARTBEAT rather than hiding behind it.
  'REBOOT_LOOP',
  'NO_HEARTBEAT',
  'NO_CONSUMER',
  'CURSOR_STALLED',
  'EMPTY_RUNS',
  'RUN_OVERDUE',
  'RUN_STALE',
  'NEVER_RUN',
  'MANUALLY_STOPPED',
  // Configuration findings rank below every runtime one: they never explain why
  // a source stopped working, so they must not take the summary headline from
  // something that does.
  'USER_MISSING',
  'USER_DISABLED',
  'TOKEN_EXPIRED',
  'USER_MISSING_CAPABILITY',
  'CONTRACT_CONFIG_INCOMPLETE',
  'DUPLICATE_QUEUE',
  'USER_NOT_SERVICE_ACCOUNT',
  'TOKEN_EXPIRING',
  'VERSION_MISMATCH',
  'EMPTY_SCOPE',
  'CONFIDENCE_UNSET',
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

  // -- stability -----------------------------------------------------------
  if (profile.stability && input.is_managed) {
    const windowSeconds = thresholds.restartDeltaWindowSeconds;
    const windowLabel = windowSeconds >= 120
      ? `${Math.round(windowSeconds / 60)} minutes`
      : `${windowSeconds} seconds`;
    if (input.is_in_reboot_loop) {
      // The composer has already concluded it is looping; trust it over our own
      // arithmetic, and report the count it observed.
      checks.push(buildCheck('REBOOT_LOOP', 'blocking', {
        count: input.restart_count ?? 0,
        window: windowLabel,
      }));
    } else if (input.restart_count !== undefined && input.previous?.last_restart_count !== undefined) {
      const delta = input.restart_count - input.previous.last_restart_count;
      // A counter that went backwards means the composer restarted and reset
      // it, not that the connector un-restarted. Ignore rather than alert.
      if (delta >= thresholds.restartDeltaThreshold) {
        checks.push(buildCheck('REBOOT_LOOP', 'blocking', { count: delta, window: windowLabel }));
      }
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

// region configuration
//
// Static, human-caused and fixable by a person. It drifts — someone converts a
// service account into a normal user, revokes a capability, lets a token expire
// — so it is re-evaluated every cycle rather than only at write time.
//
// Applies to all seven source kinds: a TAXII feed ingesting as a personal
// account is the same problem as a connector doing it.

const CONFIGURATION_RANK: Record<IngestionConfigurationStatus, number> = { ok: 0, advisory: 1, blocking: 2 };

export const computeConfigurationChecks = (
  input: IngestionHealthInput,
  now: Date,
  thresholds: IngestionHealthThresholds = DEFAULT_THRESHOLDS,
): IngestionCheck[] => {
  const checks: IngestionCheck[] = [];

  // Nobody tried to resolve the configuration for this source, so there is
  // nothing to say about it. Reporting USER_MISSING here would turn a failed
  // cache read into a fleet-wide critical.
  if (!input.configuration_checked) {
    return checks;
  }

  // -- the ingesting user --------------------------------------------------
  if (!input.user_id) {
    checks.push(buildConfigurationCheck('USER_MISSING', 'blocking'));
  } else if (!input.user) {
    // Configured but unresolvable: the user was deleted out from under it.
    checks.push(buildConfigurationCheck('USER_MISSING', 'blocking'));
  } else {
    const user = input.user;
    const userName = user.name ?? input.user_id;
    if (user.account_status && user.account_status !== 'Active') {
      checks.push(buildConfigurationCheck('USER_DISABLED', 'blocking', { user: userName }));
    }
    if (user.service_account === false) {
      // Advisory on purpose: it ingests perfectly well. It must never page
      // anyone, but it belongs in a digest and on the row.
      checks.push(buildConfigurationCheck('USER_NOT_SERVICE_ACCOUNT', 'advisory', { user: userName }));
    }
    const expiry = user.api_token_expiration ? new Date(user.api_token_expiration) : undefined;
    if (expiry && !Number.isNaN(expiry.getTime())) {
      const secondsLeft = Math.floor((expiry.getTime() - now.getTime()) / 1000);
      if (secondsLeft <= 0) {
        checks.push(buildConfigurationCheck('TOKEN_EXPIRED', 'blocking', { since: expiry.toISOString() }));
      } else if (secondsLeft <= thresholds.tokenExpiryWarningDays * 86400) {
        checks.push(buildConfigurationCheck('TOKEN_EXPIRING', 'advisory', { expires_at: expiry.toISOString() }));
      }
    }
    if (user.effective_confidence_level === null || user.effective_confidence_level === undefined) {
      checks.push(buildConfigurationCheck('CONFIDENCE_UNSET', 'advisory', { user: userName }));
    }
  }

  // -- the source's own settings -------------------------------------------
  if (input.source_kind === 'connector') {
    // Scope is what routes work to a connector; an empty one on a type that
    // needs it means nothing will ever be dispatched to it.
    const needsScope = input.connector_type === 'INTERNAL_ENRICHMENT'
      || input.connector_type === 'INTERNAL_IMPORT_FILE'
      || input.connector_type === 'INTERNAL_EXPORT_FILE';
    if (needsScope && (input.connector_scope ?? []).length === 0) {
      checks.push(buildConfigurationCheck('EMPTY_SCOPE', 'advisory'));
    }
    if ((input.contract_missing_fields ?? []).length > 0) {
      checks.push(buildConfigurationCheck('CONTRACT_CONFIG_INCOMPLETE', 'blocking', {
        fields: (input.contract_missing_fields ?? []).join(', '),
      }));
    }
    if (input.version_mismatch_image) {
      checks.push(buildConfigurationCheck('VERSION_MISMATCH', 'advisory', { image: input.version_mismatch_image }));
    }
  }
  if (input.duplicate_queue) {
    checks.push(buildConfigurationCheck('DUPLICATE_QUEUE', 'blocking'));
  }

  return rankChecks(checks);
};

export const foldConfigurationStatus = (checks: IngestionCheck[]): IngestionConfigurationStatus => {
  const configuration = checks.filter((c) => c.kind === 'configuration');
  if (configuration.some((c) => c.severity === 'blocking')) {
    return 'blocking';
  }
  return configuration.length > 0 ? 'advisory' : 'ok';
};

export const isConfigurationWorse = (
  from: IngestionConfigurationStatus,
  to: IngestionConfigurationStatus,
): boolean => CONFIGURATION_RANK[to] > CONFIGURATION_RANK[from];

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
'last_run_at' | 'last_cursor_hash' | 'consecutive_empty_runs' | 'last_restart_count' | 'restart_count_since'
>;

// The restart baseline is a *window*, not the previous cycle. Comparing against
// the last evaluation would mean REBOOT_LOOP fires only on three restarts inside
// one 60-second tick, and the message would claim a 15-minute window it never
// measured. The baseline is taken once and held until the window expires.
const advanceRestartBaseline = (
  input: IngestionHealthInput,
  previous: IngestionHealthObservation | null | undefined,
  now: Date,
  thresholds: IngestionHealthThresholds,
): Pick<ProductivityCounters, 'last_restart_count' | 'restart_count_since'> => {
  // No metrics this cycle: hold whatever baseline we had. Resetting it to zero
  // would read as a burst of restarts the moment the composer came back.
  if (input.restart_count === undefined) {
    return {
      last_restart_count: previous?.last_restart_count,
      restart_count_since: previous?.restart_count_since,
    };
  }
  const takenAt = previous?.restart_count_since ? new Date(previous.restart_count_since) : null;
  const windowExpired = !takenAt
    || Number.isNaN(takenAt.getTime())
    || (now.getTime() - takenAt.getTime()) / 1000 >= thresholds.restartDeltaWindowSeconds;
  // A counter that went backwards means the composer restarted and reset it, so
  // re-baseline rather than carry a baseline the counter can never reach again.
  const wentBackwards = previous?.last_restart_count !== undefined
    && input.restart_count < previous.last_restart_count;
  if (windowExpired || wentBackwards) {
    return { last_restart_count: input.restart_count, restart_count_since: now.toISOString() };
  }
  return {
    last_restart_count: previous?.last_restart_count,
    restart_count_since: previous?.restart_count_since,
  };
};

export const advanceProductivityCounters = (
  input: IngestionHealthInput,
  previous: IngestionHealthObservation | null | undefined,
  now: Date = new Date(),
  thresholds: IngestionHealthThresholds = DEFAULT_THRESHOLDS,
): ProductivityCounters => {
  const lastRunAt = input.last_run_at?.toISOString();

  // A connector counts empty runs from its works, which carry a real per-run
  // object count, so the input value is already authoritative.
  if (input.source_kind === 'connector') {
    return {
      last_run_at: lastRunAt,
      last_cursor_hash: input.cursor_hash ?? previous?.last_cursor_hash,
      consecutive_empty_runs: input.consecutive_empty_runs ?? 0,
      ...advanceRestartBaseline(input, previous, now, thresholds),
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
      last_restart_count: previous?.last_restart_count,
      restart_count_since: previous?.restart_count_since,
    };
  }
  const moved = input.cursor_hash !== undefined && input.cursor_hash !== previous?.last_cursor_hash;
  return {
    last_run_at: lastRunAt,
    last_cursor_hash: input.cursor_hash ?? previous?.last_cursor_hash,
    consecutive_empty_runs: moved ? 0 : carried + 1,
    last_restart_count: previous?.last_restart_count,
    restart_count_since: previous?.restart_count_since,
  };
};

// endregion

export const computeIngestionHealth = (
  input: IngestionHealthInput,
  now: Date,
  thresholds: IngestionHealthThresholds = DEFAULT_THRESHOLDS,
): IngestionHealth => {
  const runtimeChecks = computeIngestionChecks(input, now, thresholds);
  const configurationChecks = computeConfigurationChecks(input, now, thresholds);
  const configurationStatus = foldConfigurationStatus(configurationChecks);

  let status = foldRuntimeStatus(runtimeChecks, input, now);
  // A source that cannot work as configured is not merely misconfigured. The
  // escalation goes one way only: an advisory finding never touches the runtime
  // status, and a stopped source stays stopped — someone switched it off, and
  // its configuration is not an incident until they switch it back on.
  if (configurationStatus === 'blocking' && status !== 'stopped') {
    status = 'critical';
  }

  // One ranked list, both kinds, so the summary headline is whatever is most
  // diagnostic overall — in practice always a runtime check when there is one.
  const checks = rankChecks([...runtimeChecks, ...configurationChecks]);
  const changed = input.previous?.status !== status;
  return {
    status,
    configuration_status: configurationStatus,
    summary: buildSummary(status, checks),
    checks,
    since: changed || !input.previous ? now : new Date(input.previous.since),
    last_productive_at: input.last_productive_at,
    next_expected_at: input.next_expected_at,
  };
};
