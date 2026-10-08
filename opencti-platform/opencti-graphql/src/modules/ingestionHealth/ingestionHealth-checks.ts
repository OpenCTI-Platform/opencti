import { CONNECTOR_HEARTBEAT_TIMEOUT_SECONDS } from '../../database/connector-liveness';
import type { HeartbeatObservation, IngestionActingUser, IngestionCheck, IngestionHealth, IngestionHealthInput } from './ingestionHealth-types';

// pycti pings every 40 seconds. With the default 60 seconds manager period, a live connector shows
// a new ping 40 to 80 seconds after the previous one; with a period P, up to P + 40 seconds after it.
// Hence a bound of 2 periods, never below 120 seconds.
export const MIN_CLOSE_PINGS_BOUND_SECONDS = 120;
export const closePingsBoundSeconds = (managerPeriodSeconds: number) => Math.max(MIN_CLOSE_PINGS_BOUND_SECONDS, 2 * managerPeriodSeconds);
// A legacy run-and-terminate connector shows at most two pings per run: its registration,
// then force_ping at exit (sometimes doubled). Three close pings in a row cannot come from it.
export const REGULAR_PING_MIN_STREAK = 3;

const secondsBetween = (from: Date, to: Date) => (to.getTime() - from.getTime()) / 1000;

// The manager memory of a connector heartbeat: how many pings in a row came close to each other.
export interface ObservationOptions {
  // Max gap between two close pings, from closePingsBoundSeconds
  boundSeconds?: number;
  // The manager itself did not look for longer than the bound (platform restart, lost lock...).
  // A wide gap then says nothing about the connector: the count of a connector already seen
  // pinging every 40 seconds is kept as is; any other count restarts as usual.
  managerWasBlind?: boolean;
}

export const nextHeartbeatObservation = (previous: HeartbeatObservation | null, lastSeenAt: Date | null, options: ObservationOptions = {}): HeartbeatObservation => {
  const { boundSeconds = MIN_CLOSE_PINGS_BOUND_SECONDS, managerWasBlind = false } = options;
  if (!lastSeenAt) {
    return previous ?? { last_seen_at: null, close_pings: 0 };
  }
  const lastSeen = lastSeenAt.toISOString();
  if (previous?.last_seen_at === lastSeen) {
    return previous; // No new ping since the last observation
  }
  if (!previous?.last_seen_at) {
    return { last_seen_at: lastSeen, close_pings: 0 };
  }
  const gapSeconds = secondsBetween(new Date(previous.last_seen_at), lastSeenAt);
  // NaN (unreadable previous date) and negative gaps restart the count too
  const isClose = gapSeconds > 0 && gapSeconds <= boundSeconds;
  const previousCount = Number.isInteger(previous.close_pings) ? previous.close_pings : 0;
  if (isClose) {
    return { last_seen_at: lastSeen, close_pings: Math.min(previousCount + 1, REGULAR_PING_MIN_STREAK) };
  }
  // An outage only spares a connector already seen pinging every 40 seconds. A count still being built
  // (a new connector, or a legacy run-and-terminate one) restarts, so outages can never add up into a false proof
  const isAlreadyRegular = previousCount >= REGULAR_PING_MIN_STREAK;
  return { last_seen_at: lastSeen, close_pings: managerWasBlind && isAlreadyRegular ? previousCount : 0 };
};

// Seen pinging every 40 seconds: only such a connector can be said to have stopped pinging
export const isPingingRegularly = (observation: HeartbeatObservation | null) => {
  return (observation?.close_pings ?? 0) >= REGULAR_PING_MIN_STREAK;
};

export const computeNoHeartbeatCheck = (input: IngestionHealthInput, now: Date): IngestionCheck | undefined => {
  // A run-and-terminate connector is supposed to be absent between its runs (RFC 0001 §4.2),
  // a connector not seen pinging every 40 seconds cannot be said to have stopped pinging,
  // and a connector never seen running has no baseline to judge a missing ping against.
  if (input.run_and_terminate || !input.pings_regularly || !input.last_seen_at) {
    return undefined;
  }
  if (secondsBetween(input.last_seen_at, now) < CONNECTOR_HEARTBEAT_TIMEOUT_SECONDS) {
    return undefined;
  }
  const lastSeen = input.last_seen_at.toISOString();
  return {
    kind: 'runtime',
    code: 'NO_HEARTBEAT',
    severity: 'blocking',
    params: { last_seen: lastSeen },
    message: `No ping received since ${lastSeen}`,
  };
};

// No timestamp moving with every ping here: the manager caches the summary and writes on change only
const unknownSummary = (input: IngestionHealthInput) => {
  if (input.run_and_terminate) {
    return 'Heartbeat not evaluated for run-and-terminate connectors';
  }
  if (!input.last_seen_at) {
    return 'Never seen running';
  }
  return input.pings_regularly ? 'Pinging every 40 seconds, data intake not evaluated yet' : 'No ping every 40 seconds observed, heartbeat not evaluated';
};

// Pure evaluator, called by the manager only. The UI reads what the manager cached,
// so a status shown in the UI and a status sent by a future alert can never disagree (RFC 0001 §4.4).
export const computeIngestionHealth = (input: IngestionHealthInput, now: Date): IngestionHealth => {
  const checks = [computeNoHeartbeatCheck(input, now)].filter((check): check is IngestionCheck => check !== undefined);
  // Stopped short-circuits every check: a source switched off on purpose is never painted red
  if (!input.running) {
    return { status: 'stopped', summary: 'Stopped by a user', checks };
  }
  const [headline] = checks;
  if (headline && headline.severity === 'blocking') {
    return { status: 'critical', summary: headline.message, checks };
  }
  // Never healthy in chunk 1: a ping proves the connector is alive, not that it brings data in
  return { status: 'unknown', summary: unknownSummary(input), checks };
};

// Configuration warnings (RFC 0001 §4.1): a second axis, shown on the source detail page only.
// They never change the runtime status, are never cached and never notified.
export const computeIngestionWarnings = (actingUser: IngestionActingUser | undefined): IngestionCheck[] => {
  // A missing user is USER_MISSING, deferred by the RFC: saying "not a service account" would be wrong
  if (!actingUser || actingUser.service_account) {
    return [];
  }
  // Never the user name: reading a connector only needs MODULES, while the name of its user
  // is reserved to SETTINGS_SETACCESSES (connectorUser, domain/connector.ts)
  return [{
    kind: 'configuration',
    code: 'USER_NOT_SERVICE_ACCOUNT',
    severity: 'advisory',
    params: {},
    message: 'User is not a service account',
  }];
};
