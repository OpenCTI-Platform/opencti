import { afterEach, describe, expect, it } from 'vitest';
import {
  buildHealthTransitionMessage,
  buildIngestionHealthContext,
  computeHealthTransition,
  HEALTH_NOTIFICATION_DELAY_MS,
  computeIngestionHealthChecks,
  computeIngestionHealthPatch,
  isRuntimeCheckEnabled,
  markHealthNotified,
  toGraphqlHealthChecks,
  toGraphqlIngestionHealth,
} from '../../../../src/modules/ingestionHealth/ingestionHealth-checks';
import {
  HEALTH_CHECK_FEED_AND_SYNC_EXECUTION_FAILED,
  HEALTH_CHECK_HEARTBEAT_MISSING,
  HEALTH_CHECK_REGISTRY,
  HEALTH_CHECK_USER_MISSING,
  HEALTH_CHECK_USER_NOT_SERVICE_ACCOUNT,
  type HealthCheckIngestor,
  type HealthCheckUser,
} from '../../../../src/modules/ingestionHealth/ingestionHealth-registry';
import { CONNECTOR_LIVELINESS_GRACE_PERIOD_MS } from '../../../../src/modules/connector/connector-types';
import { utcDate } from '../../../../src/utils/format';
import { IngestionHealthCheckKind, IngestionHealthCheckSeverity, IngestionHealthStatus } from '../../../../src/generated/graphql';
import { HealthTransition, type IngestionHealthFields, type StoredHealthCheck, type StoredIngestionHealth } from '../../../../src/modules/ingestionHealth/ingestionHealth-types';

const EVALUATED_AT = '2026-10-13T12:00:00.000Z';
const PREVIOUS_SINCE = '2026-10-12T08:00:00.000Z';
const SERVICE_ACCOUNT = { internal: false, user_service_account: true };
const CONTEXT = { evaluatedAt: EVALUATED_AT, pingingConnectorsIds: new Set<string>(), user: SERVICE_ACCOUNT };
const USER_MISSING: StoredHealthCheck = { health_check_code: HEALTH_CHECK_USER_MISSING, health_check_metadata: {} };
const HEARTBEAT_MISSING: StoredHealthCheck = { health_check_code: HEALTH_CHECK_HEARTBEAT_MISSING, health_check_metadata: {} };
// Not in the registry (stored by another platform version): never changes the status
const OTHER_CHECK: StoredHealthCheck = { health_check_code: 'OTHER_CHECK', health_check_metadata: {} };
const CONNECTOR = { internal_id: 'connector-id', entity_type: 'Connector' };
const FEED = { internal_id: 'feed-id', entity_type: 'IngestionRss' };
const SYNC = { internal_id: 'sync-id', entity_type: 'Sync' };
const PINGING = { pingingConnectorsIds: new Set([CONNECTOR.internal_id]) };
const NOT_PINGING = { pingingConnectorsIds: new Set<string>() };
// No proof of life nor failure on the first evaluation: unknown is stored since this evaluation
const UNKNOWN_PATCH = { ingestion_health: { status: IngestionHealthStatus.Unknown, status_since: EVALUATED_AT, health_checks: [] } };

describe('computeIngestionHealthPatch', () => {
  it('should write unknown and set since with no check on the first evaluation', () => {
    expect(computeIngestionHealthPatch({}, [], CONTEXT)).toEqual(UNKNOWN_PATCH);
  });

  it('should write degraded with the check and set since when the user is missing on the first evaluation', () => {
    const patch = computeIngestionHealthPatch({}, [USER_MISSING], CONTEXT);
    expect(patch).toEqual({
      ingestion_health: {
        status: IngestionHealthStatus.Degraded,
        health_checks: [USER_MISSING],
        status_since: EVALUATED_AT,
      },
    });
  });

  it('should return null when neither the status nor the checks changed', () => {
    const current = { ingestion_health: { status: IngestionHealthStatus.Degraded, status_since: PREVIOUS_SINCE, health_checks: [USER_MISSING] } };
    expect(computeIngestionHealthPatch(current, [USER_MISSING], CONTEXT)).toBeNull();
  });

  it('should store unknown since this evaluation when a status was stored and none can be computed anymore', () => {
    // The user was fixed but no proof of life: degraded -> unknown. The last event is kept: the recovery is due after the delay
    const current = {
      ingestion_health: {
        status: IngestionHealthStatus.Degraded,
        status_since: PREVIOUS_SINCE,
        health_checks: [USER_MISSING],
        last_event_date: PREVIOUS_SINCE,
      },
    };
    expect(computeIngestionHealthPatch(current, [], CONTEXT)).toEqual({
      ingestion_health: {
        status: IngestionHealthStatus.Unknown,
        status_since: EVALUATED_AT,
        health_checks: [],
        last_event_date: PREVIOUS_SINCE,
      },
    });
  });

  it('should write unknown when ingestion_health is removed and no status can be computed', () => {
    expect(computeIngestionHealthPatch({ ingestion_health: null }, [], CONTEXT)).toEqual(UNKNOWN_PATCH);
  });

  it('should treat a stored check without metadata as a check with empty metadata', () => {
    const storedWithoutMetadata: StoredHealthCheck = { health_check_code: HEALTH_CHECK_USER_MISSING };
    const current = { ingestion_health: { status: IngestionHealthStatus.Degraded, status_since: PREVIOUS_SINCE, health_checks: [storedWithoutMetadata] } };
    expect(computeIngestionHealthPatch(current, [USER_MISSING], CONTEXT)).toBeNull();
  });

  it('should write the checks but keep since when only the metadata changed', () => {
    const current = { ingestion_health: { status: IngestionHealthStatus.Degraded, status_since: PREVIOUS_SINCE, health_checks: [USER_MISSING] } };
    const changedMetadata: StoredHealthCheck = { health_check_code: HEALTH_CHECK_USER_MISSING, health_check_metadata: { log: 'new log' } };
    const patch = computeIngestionHealthPatch(current, [changedMetadata], CONTEXT);
    expect(patch).toEqual({
      ingestion_health: {
        status: IngestionHealthStatus.Degraded,
        health_checks: [changedMetadata],
        status_since: PREVIOUS_SINCE,
      },
    });
  });

  it('should move since when the status changes', () => {
    // The user went missing: healthy -> degraded
    const current = { ingestion_health: { status: IngestionHealthStatus.Healthy, status_since: PREVIOUS_SINCE, health_checks: [] } };
    const patch = computeIngestionHealthPatch(current, [USER_MISSING], CONTEXT);
    expect(patch).toEqual({
      ingestion_health: {
        status: IngestionHealthStatus.Degraded,
        health_checks: [USER_MISSING],
        status_since: EVALUATED_AT,
      },
    });
  });
});

describe('computeIngestionHealthPatch with runtime data', () => {
  // runtimeData only holds the values of the checks enabled for the ingestor (see buildIngestionHealthContext): here a pinging connector
  const ALIVE = { ...CONTEXT, ...PINGING, runtimeData: { [HEALTH_CHECK_HEARTBEAT_MISSING]: EVALUATED_AT } };

  it('should be healthy with no check and a heartbeat', () => {
    expect(computeIngestionHealthPatch({}, [], ALIVE)).toEqual({
      ingestion_health: { status: IngestionHealthStatus.Healthy, status_since: EVALUATED_AT, health_checks: [] },
    });
  });

  it('should be unknown with no check and no heartbeat', () => {
    expect(computeIngestionHealthPatch({}, [], CONTEXT)).toEqual(UNKNOWN_PATCH);
  });

  it('should not be healthy when a check fails, whatever the heartbeat', () => {
    expect(computeIngestionHealthPatch({}, [USER_MISSING], ALIVE)?.ingestion_health?.status).toBe(IngestionHealthStatus.Degraded);
  });

  it('should be unknown, keeping the check, with a check unknown to this platform version', () => {
    expect(computeIngestionHealthPatch({}, [OTHER_CHECK], ALIVE)).toEqual({
      ingestion_health: { status: IngestionHealthStatus.Unknown, status_since: EVALUATED_AT, health_checks: [OTHER_CHECK] },
    });
  });

  it('should go back to unknown when the heartbeat expires', () => {
    const current = { ingestion_health: { status: IngestionHealthStatus.Healthy, status_since: PREVIOUS_SINCE, health_checks: [] } };
    expect(computeIngestionHealthPatch(current, [], CONTEXT)).toEqual({
      ingestion_health: { status: IngestionHealthStatus.Unknown, status_since: EVALUATED_AT, health_checks: [] },
    });
  });

  it('should keep since while the ingestion stays unknown', () => {
    const current = { ingestion_health: { status: IngestionHealthStatus.Unknown, status_since: PREVIOUS_SINCE, health_checks: [] } };
    expect(computeIngestionHealthPatch(current, [], CONTEXT)).toBeNull();
  });

  it('should be unknown, not healthy, on a stale heartbeat', () => {
    const heartbeat = utcDate(EVALUATED_AT).subtract(CONNECTOR_LIVELINESS_GRACE_PERIOD_MS, 'ms').toISOString();
    expect(computeIngestionHealthPatch({}, [], { ...CONTEXT, runtimeData: { [HEALTH_CHECK_HEARTBEAT_MISSING]: heartbeat } })).toEqual(UNKNOWN_PATCH);
  });

  it('should keep since while the ingestion stays healthy', () => {
    const current = { ingestion_health: { status: IngestionHealthStatus.Healthy, status_since: PREVIOUS_SINCE, health_checks: [] } };
    expect(computeIngestionHealthPatch(current, [], ALIVE)).toBeNull();
  });

  it('should be critical with a missing heartbeat check, even when the user is also missing', () => {
    const checks = [USER_MISSING, HEARTBEAT_MISSING];
    expect(computeIngestionHealthPatch({}, checks, CONTEXT)?.ingestion_health?.status).toBe(IngestionHealthStatus.Critical);
  });
});

describe('heartbeat check', () => {
  const input = { ...CONNECTOR, connector_user_id: 'user' };

  it('should flag a missing heartbeat when the source reports one', () => {
    expect(computeIngestionHealthChecks(input, { ...CONTEXT, ...PINGING })).toEqual([HEARTBEAT_MISSING]);
    expect(computeIngestionHealthChecks(input, { ...CONTEXT, ...PINGING, runtimeData: {} })).toEqual([HEARTBEAT_MISSING]);
  });

  it('should not flag a heartbeat that is there', () => {
    expect(computeIngestionHealthChecks(input, { ...CONTEXT, ...PINGING, runtimeData: { [HEALTH_CHECK_HEARTBEAT_MISSING]: EVALUATED_AT } })).toEqual([]);
  });

  it('should not flag a heartbeat younger than the max age', () => {
    const heartbeat = utcDate(EVALUATED_AT).subtract(CONNECTOR_LIVELINESS_GRACE_PERIOD_MS - 1000, 'ms').toISOString();
    expect(computeIngestionHealthChecks(input, { ...CONTEXT, ...PINGING, runtimeData: { [HEALTH_CHECK_HEARTBEAT_MISSING]: heartbeat } })).toEqual([]);
  });

  it('should flag a heartbeat older than the max age as missing', () => {
    const heartbeat = utcDate(EVALUATED_AT).subtract(CONNECTOR_LIVELINESS_GRACE_PERIOD_MS, 'ms').toISOString();
    const runtimeData = { [HEALTH_CHECK_HEARTBEAT_MISSING]: heartbeat };
    expect(computeIngestionHealthChecks(input, { ...CONTEXT, ...PINGING, runtimeData })).toEqual([HEARTBEAT_MISSING]);
  });

  it('should not flag a heartbeat in the future, clock skew between nodes', () => {
    const heartbeat = utcDate(EVALUATED_AT).add(10_000, 'ms').toISOString();
    expect(computeIngestionHealthChecks(input, { ...CONTEXT, ...PINGING, runtimeData: { [HEALTH_CHECK_HEARTBEAT_MISSING]: heartbeat } })).toEqual([]);
  });

  it('should not flag sources without heartbeat, such as feeds and syncs', () => {
    expect(computeIngestionHealthChecks({ ...FEED, user_id: 'user' }, { ...CONTEXT, ...PINGING })).toEqual([]);
  });

  it('should not flag connectors not pinging continuously, such as run and terminate ones', () => {
    expect(computeIngestionHealthChecks(input, { ...CONTEXT, ...NOT_PINGING })).toEqual([]);
  });

  it('should be healthy with a fresh heartbeat when the connector pings continuously', () => {
    const context = buildIngestionHealthContext(input, { ...CONTEXT, ...PINGING, runtimeData: { [HEALTH_CHECK_HEARTBEAT_MISSING]: EVALUATED_AT } });
    expect(computeIngestionHealthPatch({}, computeIngestionHealthChecks(input, context), context)?.ingestion_health?.status).toBe(IngestionHealthStatus.Healthy);
  });

  it('should give an unknown status with a fresh heartbeat when the connector does not ping continuously, such as after a run and terminate run', () => {
    const context = buildIngestionHealthContext(input, { ...CONTEXT, ...NOT_PINGING, runtimeData: { [HEALTH_CHECK_HEARTBEAT_MISSING]: EVALUATED_AT } });
    expect(computeIngestionHealthPatch({}, computeIngestionHealthChecks(input, context), context)).toEqual(UNKNOWN_PATCH);
  });

  it('should give a critical status with the check message', () => {
    const patch = computeIngestionHealthPatch({}, computeIngestionHealthChecks(input, { ...CONTEXT, ...PINGING }), CONTEXT);
    expect(patch?.ingestion_health?.status).toBe(IngestionHealthStatus.Critical);
    expect(toGraphqlIngestionHealth(patch?.ingestion_health, CONNECTOR.entity_type)?.healthChecks).toEqual([{
      health_check_code: HEALTH_CHECK_HEARTBEAT_MISSING,
      health_check_message: 'No heartbeat received',
      health_check_kind: IngestionHealthCheckKind.Runtime,
      health_check_severity: IngestionHealthCheckSeverity.Blocking,
    }]);
  });
});

describe('isRuntimeCheckEnabled', () => {
  // Tells the manager whether the runtime data must be read: true only for the ingestions a runtime check is enabled for
  it('should be true for a connector pinging continuously', () => {
    expect(isRuntimeCheckEnabled(CONNECTOR, { ...CONTEXT, ...PINGING })).toBe(true);
  });

  it('should be false for a connector not pinging continuously', () => {
    expect(isRuntimeCheckEnabled(CONNECTOR, { ...CONTEXT, ...NOT_PINGING })).toBe(false);
  });

  it('should be true for feeds and syncs, whose last execution is checked', () => {
    expect(isRuntimeCheckEnabled(FEED, { ...CONTEXT, ...NOT_PINGING })).toBe(true);
    expect(isRuntimeCheckEnabled(SYNC, { ...CONTEXT, ...NOT_PINGING })).toBe(true);
  });
});

describe('execution failed check', () => {
  const NOT_FOUND = { http_status: 404, http_status_text: 'Not Found', error_code: 'ERR_BAD_REQUEST' };
  const FEEDS_AND_SYNC_OUTCOME_TIMESTAMP = Date.parse(EVALUATED_AT);
  const failedWith = (meta?: Record<string, unknown>) => ({ ...CONTEXT, ...NOT_PINGING, runtimeData: { [HEALTH_CHECK_FEED_AND_SYNC_EXECUTION_FAILED]: { timestamp: FEEDS_AND_SYNC_OUTCOME_TIMESTAMP, level: 'error' as const, meta } } });
  const messageOf = (meta?: Record<string, unknown>, ingestor = FEED) => {
    return toGraphqlHealthChecks(computeIngestionHealthChecks(ingestor, failedWith(meta)), ingestor.entity_type)[0]?.health_check_message;
  };

  it('should flag a feed or sync whose last execution failed, with the details of the failure', () => {
    expect(computeIngestionHealthChecks(FEED, failedWith(NOT_FOUND)))
      .toEqual([{ health_check_code: HEALTH_CHECK_FEED_AND_SYNC_EXECUTION_FAILED, health_check_metadata: NOT_FOUND }]);
  });

  it.each(['IngestionRss', 'IngestionCsv', 'IngestionJson', 'IngestionTaxii', 'Sync'])('should evaluate %s', (entityType) => {
    expect(computeIngestionHealthChecks({ ...FEED, entity_type: entityType }, failedWith(NOT_FOUND))).toHaveLength(1);
  });

  it.each(['IngestionTaxiiCollection', 'Connector'])('should not evaluate %s, not executed by the ingestion or sync manager', (entityType) => {
    expect(computeIngestionHealthChecks({ ...FEED, entity_type: entityType }, failedWith(NOT_FOUND))).toEqual([]);
  });

  it('should not flag a feed or sync whose last execution succeeded, or that has no execution logged', () => {
    const checksContext = { ...CONTEXT, ...NOT_PINGING };
    expect(computeIngestionHealthChecks(FEED, { ...checksContext, runtimeData: { [HEALTH_CHECK_FEED_AND_SYNC_EXECUTION_FAILED]: { timestamp: FEEDS_AND_SYNC_OUTCOME_TIMESTAMP, level: 'success' } } })).toEqual([]);
    expect(computeIngestionHealthChecks(FEED, { ...checksContext, runtimeData: {} })).toEqual([]);
  });

  it('should give a critical status', () => {
    const patch = computeIngestionHealthPatch({}, computeIngestionHealthChecks(FEED, failedWith(NOT_FOUND)), CONTEXT);
    expect(patch?.ingestion_health?.status).toBe(IngestionHealthStatus.Critical);
  });

  it.each([
    ['an HTTP status', NOT_FOUND, 'Feed execution failed: HTTP 404 Not Found'],
    ['an HTTP status without text', { http_status: 500 }, 'Feed execution failed: HTTP 500'],
    ['a Cloudflare challenge', { http_status: 403, http_status_text: 'Forbidden', cloudflare: 'Cloudflare challenge fail' }, 'Feed execution failed: HTTP 403 Forbidden (Cloudflare challenge fail)'],
    ['a network error', { error_code: 'ECONNABORTED' }, 'Feed execution failed: ECONNABORTED'],
    ['another error', { error: 'Invalid JSON feed configuration' }, 'Feed execution failed: Invalid JSON feed configuration'],
    ['no details', undefined, 'Feed execution failed'],
  ])('should describe %s in the message', (_, meta, message) => {
    expect(messageOf(meta)).toBe(message);
  });

  it('should name a sync in the message', () => {
    expect(messageOf(NOT_FOUND, SYNC)).toBe('Sync execution failed: HTTP 404 Not Found');
    expect(messageOf(undefined, SYNC)).toBe('Sync execution failed');
  });
});

describe('check metadata', () => {
  const TEST_CODE = 'TEST_CHECK';
  const registry = HEALTH_CHECK_REGISTRY as Record<string, unknown>;
  const checksContext = { ...CONTEXT, ...NOT_PINGING };
  const failWith = (metadata: Record<string, unknown> | null) => {
    registry[TEST_CODE] = {
      kind: IngestionHealthCheckKind.Configuration,
      severity: IngestionHealthCheckSeverity.Advisory,
      message: (data: Record<string, unknown>) => `Failing for ${data.reason}`,
      isEnabled: () => true,
      getFailure: () => metadata,
    };
  };

  afterEach(() => {
    delete registry[TEST_CODE];
  });

  it('should store the metadata of a failing check, and give it to its message', () => {
    failWith({ reason: 'test' });
    const checks = computeIngestionHealthChecks(CONNECTOR, checksContext);
    expect(checks).toContainEqual({ health_check_code: TEST_CODE, health_check_metadata: { reason: 'test' } });
    expect(toGraphqlHealthChecks(checks, CONNECTOR.entity_type).find((check) => check.health_check_code === TEST_CODE)?.health_check_message).toBe('Failing for test');
  });

  it('should not store a check that passes', () => {
    failWith(null);
    expect(computeIngestionHealthChecks(CONNECTOR, checksContext).map((check) => check.health_check_code)).not.toContain(TEST_CODE);
  });
});

describe('computeIngestionHealthChecks', () => {
  // The user is resolved by the manager: undefined when not set or deleted
  const checksFor = (ingestor: HealthCheckIngestor, user?: HealthCheckUser) => computeIngestionHealthChecks(ingestor, { ...CONTEXT, ...NOT_PINGING, user });

  describe('connector (user required)', () => {
    it.each([undefined, null, ''])('should flag USER_MISSING when the user is %s', (userId) => {
      expect(checksFor({ ...CONNECTOR, connector_user_id: userId })).toEqual([USER_MISSING]);
    });

    it('should flag USER_MISSING when the user was deleted', () => {
      expect(checksFor({ ...CONNECTOR, connector_user_id: 'deleted-user-id' })).toEqual([USER_MISSING]);
    });

    it('should return no check when the user exists', () => {
      expect(checksFor({ ...CONNECTOR, connector_user_id: 'user-id' }, SERVICE_ACCOUNT)).toEqual([]);
    });
  });

  describe('feed or sync (user optional: runs as the system user without one)', () => {
    it.each([undefined, null, ''])('should return no check when the user is %s', (userId) => {
      expect(checksFor({ ...FEED, user_id: userId })).toEqual([]);
    });

    it('should flag USER_MISSING when the user was deleted', () => {
      expect(checksFor({ ...FEED, user_id: 'deleted-user-id' })).toEqual([USER_MISSING]);
    });

    it('should return no check when the user exists', () => {
      expect(checksFor({ ...FEED, user_id: 'user-id' }, SERVICE_ACCOUNT)).toEqual([]);
    });
  });

  it('should make the status degraded through computeIngestionHealthPatch when the user is missing', () => {
    const checks = checksFor({ ...CONNECTOR, connector_user_id: 'deleted-user-id' });
    expect(computeIngestionHealthPatch({}, checks, CONTEXT)?.ingestion_health?.status).toBe(IngestionHealthStatus.Degraded);
  });
});

describe('user not service account check', () => {
  const REGULAR_USER = { internal: false, user_service_account: false };
  const INTERNAL_USER = { internal: true, user_service_account: false };
  const checksFor = (ingestor: HealthCheckIngestor, user?: HealthCheckUser) => computeIngestionHealthChecks(ingestor, { ...CONTEXT, ...NOT_PINGING, user });
  const NOT_SERVICE_ACCOUNT: StoredHealthCheck = { health_check_code: HEALTH_CHECK_USER_NOT_SERVICE_ACCOUNT, health_check_metadata: {} };

  it.each([
    ['connector', { ...CONNECTOR, connector_user_id: 'user-id' }],
    ['feed', { ...FEED, user_id: 'user-id' }],
  ])('should flag a %s running as a regular user', (_, ingestor) => {
    expect(checksFor(ingestor, REGULAR_USER)).toEqual([NOT_SERVICE_ACCOUNT]);
  });

  it.each([
    ['connector', { ...CONNECTOR, connector_user_id: 'user-id' }],
    ['feed', { ...FEED, user_id: 'user-id' }],
  ])('should not flag a %s running as a service account', (_, ingestor) => {
    expect(checksFor(ingestor, SERVICE_ACCOUNT)).toEqual([]);
  });

  it('should not judge an internal user, such as the system user', () => {
    expect(checksFor({ ...FEED, user_id: 'system-id' }, INTERNAL_USER)).toEqual([]);
  });

  it('should not judge a missing user: reported by USER_MISSING only', () => {
    expect(checksFor({ ...CONNECTOR, connector_user_id: 'deleted-user-id' })).toEqual([USER_MISSING]);
    expect(checksFor({ ...CONNECTOR, connector_user_id: null })).toEqual([USER_MISSING]);
  });

  it('should not judge a feed without user: it runs as the system user', () => {
    expect(checksFor({ ...FEED, user_id: null })).toEqual([]);
  });

  it('should make the status degraded with an advisory configuration check', () => {
    const checks = checksFor({ ...CONNECTOR, connector_user_id: 'user-id' }, REGULAR_USER);
    const patch = computeIngestionHealthPatch({}, checks, CONTEXT);
    expect(patch?.ingestion_health?.status).toBe(IngestionHealthStatus.Degraded);
    expect(toGraphqlIngestionHealth(patch?.ingestion_health, CONNECTOR.entity_type)?.healthChecks).toEqual([{
      health_check_code: HEALTH_CHECK_USER_NOT_SERVICE_ACCOUNT,
      health_check_message: 'User is not a service account',
      health_check_kind: IngestionHealthCheckKind.Configuration,
      health_check_severity: IngestionHealthCheckSeverity.Advisory,
    }]);
  });
});

describe('toGraphqlIngestionHealth', () => {
  it('should return null when the ingestion was never evaluated', () => {
    expect(toGraphqlIngestionHealth(undefined, CONNECTOR.entity_type)).toBeNull();
  });

  it('should expose status and since, and the checks enriched from the registry', () => {
    const health = { status: IngestionHealthStatus.Degraded, status_since: PREVIOUS_SINCE, health_checks: [USER_MISSING] };
    expect(toGraphqlIngestionHealth(health, CONNECTOR.entity_type)).toEqual({
      status: IngestionHealthStatus.Degraded,
      status_since: PREVIOUS_SINCE,
      healthChecks: [{
        health_check_code: HEALTH_CHECK_USER_MISSING,
        health_check_message: 'User is missing',
        health_check_kind: IngestionHealthCheckKind.Configuration,
        health_check_severity: IngestionHealthCheckSeverity.Blocking,
      }],
    });
  });

  it('should drop the checks unknown to the registry and return no check when none is stored', () => {
    const healthy = { status: IngestionHealthStatus.Healthy, status_since: PREVIOUS_SINCE };
    expect(toGraphqlIngestionHealth({ ...healthy, health_checks: [OTHER_CHECK] }, CONNECTOR.entity_type)?.healthChecks).toEqual([]);
    expect(toGraphqlIngestionHealth(healthy, CONNECTOR.entity_type)?.healthChecks).toEqual([]);
  });
});

describe('computeHealthTransition', () => {
  const SINCE = '2026-10-13T11:00:00.000Z';
  const OLD_EVENT = '2026-10-13T10:00:00.000Z';
  const at = (ms: number) => new Date(new Date(SINCE).getTime() + ms).toISOString();
  const AFTER_DELAY = at(HEALTH_NOTIFICATION_DELAY_MS);
  const BEFORE_DELAY = at(HEALTH_NOTIFICATION_DELAY_MS - 1);
  const { Critical, Degraded, Healthy, Unknown } = IngestionHealthStatus;
  const health = (status: IngestionHealthStatus, last_event_date?: string): StoredIngestionHealth => (
    { status, status_since: SINCE, health_checks: [], ...(last_event_date ? { last_event_date } : {}) }
  );

  it('should return null without health: never evaluated with a status, or stopped', () => {
    expect(computeHealthTransition(undefined, AFTER_DELAY)).toBeNull();
    expect(computeHealthTransition(null, AFTER_DELAY)).toBeNull();
  });

  describe('delay', () => {
    it.each(Object.values(IngestionHealthStatus))('should defer %s inside the delay', (status) => {
      expect(computeHealthTransition(health(status, OLD_EVENT), SINCE)).toBeNull();
      expect(computeHealthTransition(health(status, OLD_EVENT), BEFORE_DELAY)).toBeNull();
    });

    it.each(Object.values(IngestionHealthStatus))('should report %s exactly when the delay is elapsed', (status) => {
      expect(computeHealthTransition(health(status, OLD_EVENT), AFTER_DELAY)).not.toBeNull();
    });
  });

  describe('already notified', () => {
    it.each(Object.values(IngestionHealthStatus))('should not report %s again when the last event is after its start', (status) => {
      expect(computeHealthTransition(health(status, AFTER_DELAY), at(10 * HEALTH_NOTIFICATION_DELAY_MS))).toBeNull();
    });

    it.each(Object.values(IngestionHealthStatus))('should report %s when the last event is at its start: strictly after is required', (status) => {
      expect(computeHealthTransition(health(status, SINCE), AFTER_DELAY)).not.toBeNull();
    });
  });

  describe('failure', () => {
    it.each([
      [Critical, HealthTransition.Critical],
      [Degraded, HealthTransition.Degraded],
    ])('should report %s, whatever the last event', (status, expected) => {
      expect(computeHealthTransition(health(status), AFTER_DELAY)).toBe(expected);
      expect(computeHealthTransition(health(status, OLD_EVENT), AFTER_DELAY)).toBe(expected);
    });
  });

  describe('recovery', () => {
    it.each([Healthy, Unknown])('should report a recovery when %s follows a failure reported and not recovered yet', (status) => {
      expect(computeHealthTransition(health(status, OLD_EVENT), AFTER_DELAY)).toBe(HealthTransition.Recovered);
    });

    it.each([Healthy, Unknown])('should not report %s when no failure is reported, never or already recovered: nothing to recover from', (status) => {
      expect(computeHealthTransition(health(status), AFTER_DELAY)).toBeNull();
    });
  });

  describe('markHealthNotified', () => {
    it.each([HealthTransition.Critical, HealthTransition.Degraded])('should keep the date of the %s event reported', (transition) => {
      expect(markHealthNotified(health(Critical, OLD_EVENT), transition, AFTER_DELAY)).toEqual(health(Critical, AFTER_DELAY));
      expect(markHealthNotified(health(Critical), transition, AFTER_DELAY)).toEqual(health(Critical, AFTER_DELAY));
    });

    it('should remove the failure reported once its recovery is published', () => {
      expect(markHealthNotified(health(Healthy, OLD_EVENT), HealthTransition.Recovered, AFTER_DELAY)).toEqual(health(Healthy));
    });
  });

  // Replays periods as the ingestion health manager does, through computeIngestionHealthPatch. Returns the published events.
  describe('scenarios over periods', () => {
    const MINUTE = 60 * 1000;
    const DELAY_MINUTES = HEALTH_NOTIFICATION_DELAY_MS / MINUTE;
    const checksOf = (status: IngestionHealthStatus): StoredHealthCheck[] => {
      if (status === Critical) return [HEARTBEAT_MISSING];
      if (status === Degraded) return [USER_MISSING];
      return [];
    };
    const run = (steps: [number, IngestionHealthStatus][]) => {
      let current: IngestionHealthFields = {};
      const events: [number, HealthTransition][] = [];
      steps.forEach(([minute, status]) => {
        const evaluatedAt = at(minute * MINUTE);
        // Healthy needs a proof of life: a live heartbeat. Without one and without check, the status is unknown
        const runtimeData = status === Healthy ? { [HEALTH_CHECK_HEARTBEAT_MISSING]: evaluatedAt } : {};
        const patch = computeIngestionHealthPatch(current, checksOf(status), { ...CONTEXT, ...PINGING, evaluatedAt, runtimeData });
        let next = patch ? patch.ingestion_health : current.ingestion_health;
        const transition = computeHealthTransition(next, evaluatedAt);
        if (transition) {
          events.push([minute, transition]);
          next = next ? markHealthNotified(next, transition, evaluatedAt) : next;
        }
        current = { ingestion_health: next };
      });
      return events;
    };
    const minutes = (from: number, to: number, status: IngestionHealthStatus) => (
      Array.from({ length: to - from + 1 }, (_, i): [number, IngestionHealthStatus] => [from + i, status])
    );

    it('should report a stable failure once, after the delay', () => {
      expect(run(minutes(0, 30, Critical))).toEqual([[DELAY_MINUTES, HealthTransition.Critical]]);
    });

    it('should report nothing for an ingestion always healthy', () => {
      expect(run(minutes(0, 30, Healthy))).toEqual([]);
    });

    it('should report the failure then the recovery, once each', () => {
      expect(run([...minutes(0, 10, Degraded), ...minutes(11, 30, Healthy)])).toEqual([
        [DELAY_MINUTES, HealthTransition.Degraded],
        [11 + DELAY_MINUTES, HealthTransition.Recovered],
      ]);
    });

    it('should report nothing for a status flapping faster than the delay', () => {
      const flapping = minutes(0, 30, Healthy).map(([minute]): [number, IngestionHealthStatus] => [minute, minute % 2 ? Critical : Healthy]);
      expect(run(flapping)).toEqual([]);
    });

    it('should report a degraded becoming critical, and a critical becoming degraded', () => {
      expect(run([...minutes(0, 10, Degraded), ...minutes(11, 20, Critical), ...minutes(21, 30, Degraded)])).toEqual([
        [DELAY_MINUTES, HealthTransition.Degraded],
        [11 + DELAY_MINUTES, HealthTransition.Critical],
        [21 + DELAY_MINUTES, HealthTransition.Degraded],
      ]);
    });

    it('should report the recovery of a notified failure becoming unknown after the delay, and nothing when healthy after it', () => {
      expect(run([...minutes(0, 10, Critical), ...minutes(11, 20, Unknown), ...minutes(21, 40, Healthy)])).toEqual([
        [DELAY_MINUTES, HealthTransition.Critical],
        [11 + DELAY_MINUTES, HealthTransition.Recovered],
      ]);
    });

    it('should report nothing when a failure becomes unknown inside the delay', () => {
      expect(run([...minutes(0, DELAY_MINUTES - 1, Degraded), ...minutes(DELAY_MINUTES, 30, Unknown)])).toEqual([]);
    });

    it('should report nothing between healthy and unknown, nor for an ingestion unknown from its first evaluation', () => {
      expect(run([...minutes(0, 10, Healthy), ...minutes(11, 20, Unknown), ...minutes(21, 40, Healthy)])).toEqual([]);
      expect(run([...minutes(0, 10, Unknown), ...minutes(11, 30, Healthy)])).toEqual([]);
    });

    it('should report nothing when healthy becomes unknown, even right after the recovery of a notified failure', () => {
      expect(run([...minutes(0, 10, Healthy), ...minutes(11, 30, Unknown)])).toEqual([]);
      // The recovery removed the failure reported: unknown, then healthy again, have nothing left to recover from
      expect(run([...minutes(0, 10, Critical), ...minutes(11, 20, Healthy), ...minutes(21, 40, Unknown), ...minutes(41, 60, Healthy)])).toEqual([
        [DELAY_MINUTES, HealthTransition.Critical],
        [11 + DELAY_MINUTES, HealthTransition.Recovered],
      ]);
    });

    it('should report a failure again after going back to it inside the delay: the delay runs on the status', () => {
      expect(run([...minutes(0, 10, Critical), [11, Healthy], ...minutes(12, 30, Critical)])).toEqual([
        [DELAY_MINUTES, HealthTransition.Critical],
        [12 + DELAY_MINUTES, HealthTransition.Critical],
      ]);
    });

    it('should report a recovery for each failure notified', () => {
      expect(run([...minutes(0, 10, Critical), ...minutes(11, 20, Healthy), ...minutes(21, 30, Critical), ...minutes(31, 50, Healthy)])).toEqual([
        [DELAY_MINUTES, HealthTransition.Critical],
        [11 + DELAY_MINUTES, HealthTransition.Recovered],
        [21 + DELAY_MINUTES, HealthTransition.Critical],
        [31 + DELAY_MINUTES, HealthTransition.Recovered],
      ]);
    });

    it('should report a recovery once: a failure never notified after it does not report it again', () => {
      expect(run([...minutes(0, 10, Critical), ...minutes(11, 20, Healthy), ...minutes(21, 22, Critical), ...minutes(23, 40, Healthy)])).toEqual([
        [DELAY_MINUTES, HealthTransition.Critical],
        [11 + DELAY_MINUTES, HealthTransition.Recovered],
      ]);
    });
  });
});

describe('buildHealthTransitionMessage', () => {
  const element = { name: 'My connector', entity_type: 'Connector' };

  it('should name the ingestion, the transition and the check messages', () => {
    expect(buildHealthTransitionMessage(element, HealthTransition.Degraded, [USER_MISSING]))
      .toBe('reports `My connector` (Connector) as degraded: User is missing');
  });

  it('should name the ingestion and the transition only when recovered', () => {
    expect(buildHealthTransitionMessage(element, HealthTransition.Recovered, []))
      .toBe('reports `My connector` (Connector) as recovered');
  });

  it('should ignore the checks unknown to the registry', () => {
    expect(buildHealthTransitionMessage(element, HealthTransition.Critical, [OTHER_CHECK]))
      .toBe('reports `My connector` (Connector) as critical');
  });
});
