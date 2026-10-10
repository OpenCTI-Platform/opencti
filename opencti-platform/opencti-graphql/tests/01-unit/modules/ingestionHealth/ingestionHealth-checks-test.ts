import { describe, expect, it } from 'vitest';
import {
  computeIngestionHealth,
  computeIngestionWarnings,
  closePingsBoundSeconds,
  computeNoHeartbeatCheck,
  isPingingRegularly,
  nextHeartbeatObservation,
} from '../../../../src/modules/ingestionHealth/ingestionHealth-checks';
import { CONNECTOR_HEARTBEAT_TIMEOUT_SECONDS } from '../../../../src/database/connector-liveness';
import type { HeartbeatObservation, IngestionHealthInput } from '../../../../src/modules/ingestionHealth/ingestionHealth-types';

const NOW = new Date('2026-10-07T12:00:00.000Z');
const secondsAgo = (seconds: number) => new Date(NOW.getTime() - seconds * 1000);

const input = (overrides: Partial<IngestionHealthInput> = {}): IngestionHealthInput => ({
  running: true,
  run_and_terminate: false,
  last_seen_at: secondsAgo(30),
  pings_regularly: true,
  ...overrides,
});

describe('Ingestion health evaluator - heartbeat', () => {
  it('should not fire before 5 minutes without ping, like Active/Inactive', () => {
    expect(computeNoHeartbeatCheck(input({ last_seen_at: secondsAgo(CONNECTOR_HEARTBEAT_TIMEOUT_SECONDS - 1) }), NOW)).toBeUndefined();
  });

  it('should fire from 5 minutes without ping, exactly when Active/Inactive turns inactive', () => {
    const lastSeen = secondsAgo(CONNECTOR_HEARTBEAT_TIMEOUT_SECONDS);
    expect(computeNoHeartbeatCheck(input({ last_seen_at: lastSeen }), NOW)).toEqual({
      kind: 'runtime',
      code: 'NO_HEARTBEAT',
      severity: 'blocking',
      params: { last_seen: lastSeen.toISOString() },
      message: `No ping received since ${lastSeen.toISOString()}`,
    });
  });

  it('should never fire for a connector not seen pinging every 40 seconds, like a legacy run-and-terminate one', () => {
    expect(computeNoHeartbeatCheck(input({ pings_regularly: false, last_seen_at: secondsAgo(3 * 24 * 3600) }), NOW)).toBeUndefined();
  });

  it('should never fire for a connector declaring run-and-terminate', () => {
    expect(computeNoHeartbeatCheck(input({ run_and_terminate: true, last_seen_at: secondsAgo(3 * 24 * 3600) }), NOW)).toBeUndefined();
  });

  it('should not fire for a connector never seen running, there is no baseline', () => {
    expect(computeNoHeartbeatCheck(input({ last_seen_at: null }), NOW)).toBeUndefined();
  });
});

// The observations the manager makes, one cycle after the other, of a connector pinging at these times
const observe = (pingsSecondsAgo: number[]): HeartbeatObservation | null => {
  return pingsSecondsAgo.reduce<HeartbeatObservation | null>((previous, seconds) => nextHeartbeatObservation(previous, secondsAgo(seconds)), null);
};

describe('Ingestion health evaluator - heartbeat observation', () => {
  it('should not consider a connector observed for the first time as pinging regularly', () => {
    expect(nextHeartbeatObservation(null, secondsAgo(30))).toEqual({ last_seen_at: secondsAgo(30).toISOString(), close_pings: 0 });
    expect(isPingingRegularly(null)).toBe(false);
  });

  it('should consider a connector pinging every 40 seconds as regular after 3 close pings, the manager looking every 60 seconds', () => {
    // A new ping is seen 40 or 80 seconds after the previous one
    expect(isPingingRegularly(observe([240, 200, 120]))).toBe(false); // 2 close pings
    expect(isPingingRegularly(observe([240, 200, 120, 80]))).toBe(true); // 3 close pings
  });

  it('should never consider a legacy run-and-terminate connector as regular, whatever its run length', () => {
    // Registration at start, then force_ping at exit, which can send a second ping milliseconds later
    expect(isPingingRegularly(observe([400, 310, 309.99]))).toBe(false); // a 90 seconds run, both final pings seen
    expect(isPingingRegularly(observe([400, 370]))).toBe(false); // a 30 seconds run
    expect(isPingingRegularly(observe([1000, 400]))).toBe(false); // a 10 minutes run
  });

  it('should restart the count when two pings are more than 120 seconds apart, with the default period', () => {
    const regular = { last_seen_at: secondsAgo(400).toISOString(), close_pings: 3 };
    expect(nextHeartbeatObservation(regular, secondsAgo(200))).toEqual({ last_seen_at: secondsAgo(200).toISOString(), close_pings: 0 });
    // A run hours later, or a manager down for a while
    expect(nextHeartbeatObservation(regular, secondsAgo(10)).close_pings).toBe(0);
  });

  it('should keep the observation when no new ping arrived, so a dead regular connector stays judged', () => {
    const previous = { last_seen_at: secondsAgo(900).toISOString(), close_pings: 3 };
    expect(nextHeartbeatObservation(previous, secondsAgo(900))).toBe(previous);
    expect(nextHeartbeatObservation(previous, null)).toBe(previous);
  });

  it('should cap the count, so a live connector does not grow its observation forever', () => {
    const previous = { last_seen_at: secondsAgo(80).toISOString(), close_pings: 3 };
    expect(nextHeartbeatObservation(previous, secondsAgo(40)).close_pings).toBe(3);
  });

  it('should keep the count when the gap comes from the manager not looking, not from the connector', () => {
    // Pinging every 40 seconds before a 5 minutes manager outage, and during it
    const regular = { last_seen_at: secondsAgo(400).toISOString(), close_pings: 3 };
    expect(nextHeartbeatObservation(regular, secondsAgo(10), { managerWasBlind: true })).toEqual({ last_seen_at: secondsAgo(10).toISOString(), close_pings: 3 });
  });

  it('should never let manager outages build up the count of a legacy run-and-terminate connector, run after run', () => {
    const blind = { managerWasBlind: true };
    // Run 1: registration, then force_ping doubled at exit
    let observation = nextHeartbeatObservation(null, secondsAgo(3000));
    observation = nextHeartbeatObservation(observation, secondsAgo(2910));
    observation = nextHeartbeatObservation(observation, secondsAgo(2909.99));
    expect(observation.close_pings).toBe(2);
    // Run 2 starts during a manager outage, then ends with the same exit pings
    observation = nextHeartbeatObservation(observation, secondsAgo(1000), blind);
    observation = nextHeartbeatObservation(observation, secondsAgo(910));
    observation = nextHeartbeatObservation(observation, secondsAgo(909.99));
    expect(observation.close_pings).toBe(2);
    expect(isPingingRegularly(observation)).toBe(false);
  });

  it('should restart from zero a connector not yet seen pinging every 40 seconds, after a manager outage', () => {
    const starting = { last_seen_at: secondsAgo(400).toISOString(), close_pings: 2 };
    expect(nextHeartbeatObservation(starting, secondsAgo(10), { managerWasBlind: true }).close_pings).toBe(0);
  });

  it('should derive the close-pings bound from the manager period, never below 120 seconds', () => {
    expect(closePingsBoundSeconds(60)).toBe(120); // the default period
    expect(closePingsBoundSeconds(30)).toBe(120);
    expect(closePingsBoundSeconds(300)).toBe(600);
  });

  it('should still recognize a connector pinging every 40 seconds with a 5 minutes manager period', () => {
    // The manager sees one ping every 5 minutes, up to 5 minutes 40 seconds apart
    const options = { boundSeconds: closePingsBoundSeconds(300) };
    const observation = [1400, 1080, 720, 380].reduce<HeartbeatObservation | null>((previous, seconds) => nextHeartbeatObservation(previous, secondsAgo(seconds), options), null);
    expect(isPingingRegularly(observation)).toBe(true);
    // A legacy run is still 2 pings at most
    const legacyRun = [1400, 1310, 1309.99].reduce<HeartbeatObservation | null>(
      (previous, seconds) => nextHeartbeatObservation(previous, secondsAgo(seconds), options),
      null,
    );
    expect(isPingingRegularly(legacyRun)).toBe(false);
  });

  it('should restart the count on an unreadable previous observation', () => {
    expect(nextHeartbeatObservation({ last_seen_at: 'not a date', close_pings: 3 }, secondsAgo(10)).close_pings).toBe(0);
    expect(nextHeartbeatObservation({ last_seen_at: secondsAgo(50).toISOString() } as any, secondsAgo(10)).close_pings).toBe(1);
  });
});

describe('Ingestion health evaluator - status', () => {
  it('should be unknown, never healthy, for a connector pinging every 40 seconds', () => {
    expect(computeIngestionHealth(input(), NOW)).toEqual({
      status: 'unknown',
      summary: 'Pinging every 40 seconds, data intake not evaluated yet',
      checks: [],
    });
  });

  it('should give a summary that does not move with every ping, so the manager writes on change only', () => {
    expect(computeIngestionHealth(input({ last_seen_at: secondsAgo(10) }), NOW)).toEqual(computeIngestionHealth(input({ last_seen_at: secondsAgo(50) }), NOW));
  });

  it('should be critical with the heartbeat check as summary when the ping is lost', () => {
    const lastSeen = secondsAgo(3600);
    const health = computeIngestionHealth(input({ last_seen_at: lastSeen }), NOW);
    expect(health.status).toBe('critical');
    expect(health.summary).toBe(`No ping received since ${lastSeen.toISOString()}`);
    expect(health.checks.map((check) => check.code)).toEqual(['NO_HEARTBEAT']);
  });

  it('should stay unknown for a connector not seen pinging every 40 seconds, between two runs', () => {
    expect(computeIngestionHealth(input({ last_seen_at: secondsAgo(3600), pings_regularly: false }), NOW)).toEqual({
      status: 'unknown',
      summary: 'No ping every 40 seconds observed, heartbeat not evaluated',
      checks: [],
    });
  });

  it('should explain an unknown status for a run-and-terminate connector and a never seen one', () => {
    expect(computeIngestionHealth(input({ run_and_terminate: true }), NOW).summary).toBe('Heartbeat not evaluated for run-and-terminate connectors');
    expect(computeIngestionHealth(input({ last_seen_at: null }), NOW)).toEqual({ status: 'unknown', summary: 'Never seen running', checks: [] });
  });

  it('should be stopped when switched off by a person, whatever fails, keeping the checks', () => {
    const health = computeIngestionHealth(input({ running: false, last_seen_at: secondsAgo(3600) }), NOW);
    expect(health.status).toBe('stopped');
    expect(health.summary).toBe('Stopped by a user');
    expect(health.checks.map((check) => check.code)).toEqual(['NO_HEARTBEAT']);
  });
});

describe('Ingestion health evaluator - configuration warnings', () => {
  it('should warn when the connector user is not a service account', () => {
    // No user name, neither in the message nor in the params: reading a connector only needs MODULES,
    // while the name of its user is reserved to SETTINGS_SETACCESSES (connectorUser, domain/connector.ts)
    expect(computeIngestionWarnings({ service_account: false })).toEqual([{
      kind: 'configuration',
      code: 'USER_NOT_SERVICE_ACCOUNT',
      severity: 'advisory',
      params: {},
      message: 'User is not a service account',
    }]);
  });

  it('should not warn for a service account', () => {
    expect(computeIngestionWarnings({ service_account: true })).toEqual([]);
  });

  it('should warn, as blocking, when the connector user is missing', () => {
    // Blocking since a connector without a user cannot authenticate, but still never changing the status.
    // No user id or name either: the identity of a user is reserved to SETTINGS_SETACCESSES
    expect(computeIngestionWarnings(undefined)).toEqual([{
      kind: 'configuration',
      code: 'USER_MISSING',
      severity: 'blocking',
      params: {},
      message: 'User is missing',
    }]);
  });

  it('should never add USER_NOT_SERVICE_ACCOUNT to a missing user, which cannot be a service account', () => {
    expect(computeIngestionWarnings(undefined).map((warning) => warning.code)).toEqual(['USER_MISSING']);
  });
});
