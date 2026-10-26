import { afterEach, describe, expect, it, vi } from 'vitest';
import { type IngestionLogEntry, redisGetIngestionLogHistory } from '../../../../src/database/redis';
import {
  buildHealthTransitionMessage,
  formatHealthCheckMessage,
  buildIngestionHealthContext,
  computeHealthTransition,
  DEFAULT_HEALTH_NOTIFICATION_DELAY_MS,
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
  HEALTH_CHECK_LAST_RUN_FAILED,
  HEALTH_CHECK_REGISTRY,
  HEALTH_CHECK_SOURCE_ACCESS_DENIED,
  HEALTH_CHECK_USER_MISSING,
  HEALTH_CHECK_USER_MISSING_CAPABILITY,
  HEALTH_CHECK_USER_NOT_SERVICE_ACCOUNT,
  type HealthCheckCode,
  type HealthCheckIngestor,
  type HealthCheckUser,
  type RuntimeDataReadContext,
} from '../../../../src/modules/ingestionHealth/ingestionHealth-registry';
import { CONNECTOR_LIVELINESS_GRACE_PERIOD_MS } from '../../../../src/modules/connector/connector-types';
import { utcDate } from '../../../../src/utils/format';
import { IngestionHealthCheckKind, IngestionHealthCheckSeverity, IngestionHealthStatus } from '../../../../src/generated/graphql';
import { type ConnectorWorkError, loadConnectorsRuntimeState } from '../../../../src/modules/ingestionHealth/ingestionHealth-connectorWorks';
import { HealthTransition, type IngestionHealthFields, type StoredHealthCheck, type StoredIngestionHealth } from '../../../../src/modules/ingestionHealth/ingestionHealth-types';

vi.mock('../../../../src/database/redis', async (importActual) => ({
  ...(await importActual<typeof import('../../../../src/database/redis')>()),
  redisGetIngestionLogHistory: vi.fn(),
}));
vi.mock('../../../../src/modules/ingestionHealth/ingestionHealth-connectorWorks', async (importActual) => ({
  ...(await importActual<typeof import('../../../../src/modules/ingestionHealth/ingestionHealth-connectorWorks')>()),
  loadConnectorsRuntimeState: vi.fn(),
}));

const EVALUATED_AT = '2026-10-13T12:00:00.000Z';
const PREVIOUS_SINCE = '2026-10-12T08:00:00.000Z';
const SERVICE_ACCOUNT = { internal: false, user_service_account: true, hasCapability: () => true };
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
        last_event_status: IngestionHealthStatus.Degraded,
      },
    };
    expect(computeIngestionHealthPatch(current, [], CONTEXT)).toEqual({
      ingestion_health: {
        status: IngestionHealthStatus.Unknown,
        status_since: EVALUATED_AT,
        health_checks: [],
        last_event_date: PREVIOUS_SINCE,
        last_event_status: IngestionHealthStatus.Degraded,
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
      health_check_metadata: {},
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

  it('should be false for a connector not pinging continuously whose last work is not read: a stream', () => {
    expect(isRuntimeCheckEnabled({ ...CONNECTOR, connector_type: 'STREAM' }, { ...CONTEXT, ...NOT_PINGING })).toBe(false);
  });

  it('should be true for a connector not pinging continuously whose last work is read: not a stream', () => {
    expect(isRuntimeCheckEnabled({ ...CONNECTOR, connector_type: 'EXTERNAL_IMPORT' }, { ...CONTEXT, ...NOT_PINGING })).toBe(true);
  });

  it('should be true for feeds and syncs whose last execution failed: the details of the failure are read', () => {
    expect(isRuntimeCheckEnabled({ ...FEED, last_execution_status: 'error' }, { ...CONTEXT, ...NOT_PINGING })).toBe(true);
    expect(isRuntimeCheckEnabled({ ...SYNC, last_execution_status: 'error' }, { ...CONTEXT, ...NOT_PINGING })).toBe(true);
  });

  it('should be false for feeds and syncs whose last execution did not fail: nothing to read', () => {
    expect(isRuntimeCheckEnabled({ ...FEED, last_execution_status: 'success' }, { ...CONTEXT, ...NOT_PINGING })).toBe(false);
    expect(isRuntimeCheckEnabled(FEED, { ...CONTEXT, ...NOT_PINGING })).toBe(false);
    expect(isRuntimeCheckEnabled(SYNC, { ...CONTEXT, ...NOT_PINGING })).toBe(false);
  });

  it('should be false when the only runtime check enabled for the ingestion is disabled on the platform: nothing to read', () => {
    expect(isRuntimeCheckEnabled(CONNECTOR, { ...CONTEXT, ...PINGING, disabledHealthChecks: [HEALTH_CHECK_HEARTBEAT_MISSING] })).toBe(false);
    const failingFeed = { ...FEED, last_execution_status: 'error' };
    expect(isRuntimeCheckEnabled(failingFeed, { ...CONTEXT, ...NOT_PINGING, disabledHealthChecks: [HEALTH_CHECK_FEED_AND_SYNC_EXECUTION_FAILED] })).toBe(false);
    // Another check disabled: still read
    expect(isRuntimeCheckEnabled(CONNECTOR, { ...CONTEXT, ...PINGING, disabledHealthChecks: [HEALTH_CHECK_FEED_AND_SYNC_EXECUTION_FAILED] })).toBe(true);
  });
});

describe('execution failed check', () => {
  const NOT_FOUND = { http_status: 404, http_status_text: 'Not Found', error_code: 'ERR_BAD_REQUEST' };
  const FAILED_FEED = { ...FEED, last_execution_status: 'error' };
  const FAILED_SYNC = { ...SYNC, last_execution_status: 'error' };
  // The details of the failure, read from the ingestion logs: absent when they hold none
  const failedWith = (meta?: Record<string, unknown>) => ({ ...CONTEXT, ...NOT_PINGING, runtimeData: meta ? { [HEALTH_CHECK_FEED_AND_SYNC_EXECUTION_FAILED]: meta } : {} });
  const graphqlCheckOf = (meta?: Record<string, unknown>, ingestor = FAILED_FEED) => {
    return toGraphqlHealthChecks(computeIngestionHealthChecks(ingestor, failedWith(meta)), ingestor.entity_type)[0];
  };
  // The message as shown once its placeholders are filled, as the front does after translating it
  const messageOf = (meta?: Record<string, unknown>, ingestor = FAILED_FEED) => {
    const check = graphqlCheckOf(meta, ingestor);
    return formatHealthCheckMessage(check.health_check_message ?? '', check.health_check_metadata ?? {});
  };

  it('should flag a feed or sync whose last execution failed, with the details of the failure and their description', () => {
    expect(computeIngestionHealthChecks(FAILED_FEED, failedWith(NOT_FOUND))).toEqual([{
      health_check_code: HEALTH_CHECK_FEED_AND_SYNC_EXECUTION_FAILED,
      health_check_metadata: { ...NOT_FOUND, failure_description: 'HTTP 404 Not Found' },
    }]);
  });

  it('should flag it without details when the logs hold none', () => {
    expect(computeIngestionHealthChecks(FAILED_FEED, failedWith()))
      .toEqual([{ health_check_code: HEALTH_CHECK_FEED_AND_SYNC_EXECUTION_FAILED, health_check_metadata: {} }]);
  });

  it.each(['IngestionRss', 'IngestionCsv', 'IngestionJson', 'IngestionTaxii', 'Sync'])('should evaluate %s', (entityType) => {
    expect(computeIngestionHealthChecks({ ...FAILED_FEED, entity_type: entityType }, failedWith(NOT_FOUND))).toHaveLength(1);
  });

  it.each(['IngestionTaxiiCollection', 'Connector'])('should not evaluate %s, not executed by the ingestion or sync manager', (entityType) => {
    expect(computeIngestionHealthChecks({ ...FAILED_FEED, entity_type: entityType }, failedWith(NOT_FOUND))).toEqual([]);
  });

  it('should not flag a feed or sync whose last execution succeeded, or never ran, whatever the logs hold', () => {
    expect(computeIngestionHealthChecks({ ...FEED, last_execution_status: 'success' }, failedWith(NOT_FOUND))).toEqual([]);
    expect(computeIngestionHealthChecks(FEED, failedWith(NOT_FOUND))).toEqual([]);
    expect(computeIngestionHealthChecks({ ...FEED, last_execution_status: null }, failedWith(NOT_FOUND))).toEqual([]);
  });

  it('should give a critical status', () => {
    const patch = computeIngestionHealthPatch({}, computeIngestionHealthChecks(FAILED_FEED, failedWith(NOT_FOUND)), CONTEXT);
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
    expect(messageOf(NOT_FOUND, FAILED_SYNC)).toBe('Sync execution failed: HTTP 404 Not Found');
    expect(messageOf(undefined, FAILED_SYNC)).toBe('Sync execution failed');
  });

  // The front translates the message before filling it: the details must stay out of the text to translate
  it.each([
    ['a feed', FAILED_FEED, 'Feed execution failed: {failure_description}'],
    ['a sync', FAILED_SYNC, 'Sync execution failed: {failure_description}'],
  ])('should give the message of %s as a template, the description of the failure in the metadata', (_, ingestor, template) => {
    const check = graphqlCheckOf(NOT_FOUND, ingestor);
    expect(check.health_check_message).toBe(template);
    expect(check.health_check_metadata).toEqual({ ...NOT_FOUND, failure_description: 'HTTP 404 Not Found' });
  });

  it('should give the message without placeholder nor description in the metadata when no details are known', () => {
    const check = graphqlCheckOf(undefined);
    expect(check.health_check_message).toBe('Feed execution failed');
    expect(check.health_check_metadata).toEqual({});
  });
});

describe('execution failed check details', () => {
  const readDetails = HEALTH_CHECK_REGISTRY[HEALTH_CHECK_FEED_AND_SYNC_EXECUTION_FAILED].getRuntimeData;
  // The logs are read from Redis only: the read context is not used
  const READ = {} as RuntimeDataReadContext;
  const feeds = (...ids: string[]) => ids.map((id) => ({ internal_id: id, entity_type: 'IngestionRss' }));
  const entry = (level: IngestionLogEntry['level'], meta: Record<string, unknown> = {}): IngestionLogEntry => (
    { timestamp: 1, level, type: 'rss', identifier: 'feed', message: 'm', meta }
  );
  const historiesOf = (histories: Record<string, IngestionLogEntry[]>) => {
    vi.mocked(redisGetIngestionLogHistory).mockImplementation(async (id: string) => histories[id] ?? []);
  };

  it('should read the details of the last outcome when it is a failure, skipping the progress entries', async () => {
    // Most recent first
    historiesOf({ failed: [entry('info'), entry('warn'), entry('error', { http_status: 404 }), entry('error', { http_status: 500 })] });
    expect(await readDetails(feeds('failed'), READ)).toEqual(new Map([['failed', { http_status: 404 }]]));
  });

  it('should omit a feed whose last outcome is a success, even when an older failure is still logged', async () => {
    historiesOf({ recovered: [entry('info'), entry('success'), entry('error', { http_status: 404 })] });
    expect((await readDetails(feeds('recovered'), READ)).has('recovered')).toBe(false);
  });

  it('should omit a feed whose logs hold no outcome, or no log at all: the failure is reported without details', async () => {
    historiesOf({ progress: [entry('info'), entry('warn')] });
    const details = await readDetails(feeds('progress', 'empty'), READ);
    expect(details.size).toBe(0);
  });

  it('should not hide a read failure', async () => {
    vi.mocked(redisGetIngestionLogHistory).mockRejectedValue(new Error('redis unavailable'));
    await expect(readDetails(feeds('failed'), READ)).rejects.toThrow('redis unavailable');
  });
});

describe('source access denied check', () => {
  const FAILED_FEED = { ...FEED, last_execution_status: 'error' };
  const FAILED_SYNC = { ...SYNC, last_execution_status: 'error' };
  const runtime = (details: object) => ({
    [HEALTH_CHECK_FEED_AND_SYNC_EXECUTION_FAILED]: details,
    [HEALTH_CHECK_SOURCE_ACCESS_DENIED]: details,
  });
  const ACCESS_DENIED = (http_status: number) => (
    [{ health_check_code: HEALTH_CHECK_SOURCE_ACCESS_DENIED, health_check_metadata: { http_status } }]
  );

  it('should report SOURCE_ACCESS_DENIED instead of FEED_AND_SYNC_EXECUTION_FAILED on a 401', () => {
    const checks = computeIngestionHealthChecks(FAILED_FEED, { ...CONTEXT, runtimeData: runtime({ http_status: 401, http_status_text: 'Unauthorized' }) });
    expect(checks).toEqual(ACCESS_DENIED(401));
  });

  it.each([402, 403])('should report SOURCE_ACCESS_DENIED on a %s', (status) => {
    const checks = computeIngestionHealthChecks(FAILED_FEED, { ...CONTEXT, runtimeData: runtime({ http_status: status }) });
    expect(checks).toEqual(ACCESS_DENIED(status));
  });

  it('should report it for a sync too', () => {
    const checks = computeIngestionHealthChecks(FAILED_SYNC, { ...CONTEXT, runtimeData: runtime({ http_status: 403 }) });
    expect(checks).toEqual(ACCESS_DENIED(403));
  });

  it.each([429, 500])('should keep FEED_AND_SYNC_EXECUTION_FAILED on a %s', (status) => {
    const checks = computeIngestionHealthChecks(FAILED_FEED, { ...CONTEXT, runtimeData: runtime({ http_status: status }) });
    expect(checks).toEqual([{ health_check_code: HEALTH_CHECK_FEED_AND_SYNC_EXECUTION_FAILED, health_check_metadata: { http_status: status } }]);
  });

  it('should keep FEED_AND_SYNC_EXECUTION_FAILED when the logs hold no details', () => {
    const checks = computeIngestionHealthChecks(FAILED_FEED, { ...CONTEXT, runtimeData: {} });
    expect(checks.map((check) => check.health_check_code)).toEqual([HEALTH_CHECK_FEED_AND_SYNC_EXECUTION_FAILED]);
  });

  it('should report FEED_AND_SYNC_EXECUTION_FAILED again when SOURCE_ACCESS_DENIED is disabled', () => {
    const checks = computeIngestionHealthChecks(FAILED_FEED, {
      ...CONTEXT,
      disabledHealthChecks: [HEALTH_CHECK_SOURCE_ACCESS_DENIED],
      runtimeData: runtime({ http_status: 401 }),
    });
    expect(checks.map((check) => check.health_check_code)).toEqual([HEALTH_CHECK_FEED_AND_SYNC_EXECUTION_FAILED]);
  });

  it('should not report it for a feed whose last execution did not fail', () => {
    expect(computeIngestionHealthChecks(FEED, { ...CONTEXT, runtimeData: runtime({ http_status: 401 }) })).toEqual([]);
  });

  it('should not be enabled for a connector, managed or not: its access is not checked', () => {
    const { isEnabled } = HEALTH_CHECK_REGISTRY[HEALTH_CHECK_SOURCE_ACCESS_DENIED];
    expect(isEnabled({ ...CONNECTOR, connector_type: 'EXTERNAL_IMPORT' }, NOT_PINGING)).toBe(false);
    expect(isEnabled({ ...CONNECTOR, connector_type: 'STREAM', catalog_id: 'catalog-id' } as HealthCheckIngestor, NOT_PINGING)).toBe(false);
  });

  it('should give a critical status', () => {
    const checks = computeIngestionHealthChecks(FAILED_FEED, { ...CONTEXT, runtimeData: runtime({ http_status: 401 }) });
    expect(computeIngestionHealthPatch({}, checks, CONTEXT)?.ingestion_health?.status).toBe(IngestionHealthStatus.Critical);
  });

  it.each(['IngestionRss', 'Sync'])('should word the message for a %s', (entityType) => {
    const [check] = toGraphqlHealthChecks(ACCESS_DENIED(401), entityType);
    expect(check.health_check_message).toBe('Source denied access: HTTP {http_status}');
    expect(check.health_check_severity).toBe(IngestionHealthCheckSeverity.Blocking);
    expect(check.health_check_kind).toBe(IngestionHealthCheckKind.Runtime);
  });

  it('should read the details of the failing feeds and syncs', async () => {
    const readDetails = HEALTH_CHECK_REGISTRY[HEALTH_CHECK_SOURCE_ACCESS_DENIED].getRuntimeData;
    vi.mocked(redisGetIngestionLogHistory).mockImplementation(async (id: string) => (
      id === FAILED_FEED.internal_id
        ? [{ timestamp: 1, level: 'error', type: 'rss', identifier: 'feed', message: 'm', meta: { http_status: 401 } }]
        : []
    ));
    const values = await readDetails([FAILED_FEED, FAILED_SYNC], {} as RuntimeDataReadContext);
    expect(values).toEqual(new Map([[FAILED_FEED.internal_id, { http_status: 401 }]]));
  });
});

describe('last run failed check', () => {
  const IMPORT_CONNECTOR = { ...CONNECTOR, connector_type: 'EXTERNAL_IMPORT' };
  const lastWork = (errors: ConnectorWorkError[]) => ({
    connector_type: 'EXTERNAL_IMPORT',
    connector_info: null,
    last_work: { timestamp: 't', processed_time: '2026-10-26T11:00:00Z', errors },
  });
  const evaluate = (ingestor: HealthCheckIngestor, value: object) => (
    computeIngestionHealthChecks(ingestor, { ...CONTEXT, runtimeData: { [HEALTH_CHECK_LAST_RUN_FAILED]: value as never } })
  );
  const failed = (error?: string) => [{ health_check_code: HEALTH_CHECK_LAST_RUN_FAILED, health_check_metadata: error === undefined ? {} : { error } }];

  it('should report the failure with the error, query string removed', () => {
    expect(evaluate(IMPORT_CONNECTOR, lastWork([{ message: 'Timeout calling https://api.example.com/x?key=secret', source: null }])))
      .toEqual(failed('Timeout calling https://api.example.com/x'));
  });

  it('should remove the query string of every url of the error, keeping the rest', () => {
    expect(evaluate(IMPORT_CONNECTOR, lastWork([{ message: 'GET https://a.example.com/x?token=1 then http://b.example.com/y?k=2&z=3 failed', source: null }])))
      .toEqual(failed('GET https://a.example.com/x then http://b.example.com/y failed'));
  });

  it('should remove the query string of a relative url, as urllib3 writes it', () => {
    const maxRetry = "HTTPSConnectionPool(host='api.x', port=443): Max retries exceeded with url: /v1/feed?apikey=SECRET (Caused by …)";
    expect(evaluate(IMPORT_CONNECTOR, lastWork([{ message: maxRetry, source: null }])))
      .toEqual(failed("HTTPSConnectionPool(host='api.x', port=443): Max retries exceeded with url: /v1/feed (Caused by …)"));
  });

  it('should remove the user and password of an absolute url', () => {
    expect(evaluate(IMPORT_CONNECTOR, lastWork([{ message: 'GET https://user:secret@api.example.com/x failed', source: null }])))
      .toEqual(failed('GET https://api.example.com/x failed'));
  });

  it('should stop the query string at a closing parenthesis or bracket, kept', () => {
    expect(evaluate(IMPORT_CONNECTOR, lastWork([{ message: 'Timeout (https://api.example.com/x?key=secret) [url=/y?token=1]', source: null }])))
      .toEqual(failed('Timeout (https://api.example.com/x) [url=/y]'));
  });

  it('should keep a question mark that does not follow a url or a path', () => {
    expect(evaluate(IMPORT_CONNECTOR, lastWork([{ message: 'Is the key valid? No', source: null }]))).toEqual(failed('Is the key valid? No'));
  });

  it('should scrub a long error without a space in linear time', () => {
    const [check] = evaluate(IMPORT_CONNECTOR, lastWork([{ message: `${'a/'.repeat(50000)}?key=secret`, source: null }]));
    expect(check.health_check_metadata?.error).toBe('a/'.repeat(100));
  });

  it('should truncate the error to 200 characters', () => {
    const [check] = evaluate(IMPORT_CONNECTOR, lastWork([{ message: 'a'.repeat(300), source: null }]));
    expect(check.health_check_metadata?.error).toBe('a'.repeat(200));
  });

  it('should show the error of the connector first, when the work holds several', () => {
    expect(evaluate(IMPORT_CONNECTOR, lastWork([{ message: 'closed with an error', source: null }, { message: 'Traceback: boom', source: 'CONNECTOR' }])))
      .toEqual(failed('Traceback: boom'));
  });

  it('should report the failure without error when its entry has no message', () => {
    expect(evaluate(IMPORT_CONNECTOR, lastWork([{ source: null }]))).toEqual(failed());
  });

  it('should pass on a work without error, or without conclusive work', () => {
    expect(evaluate(IMPORT_CONNECTOR, lastWork([]))).toEqual([]);
    expect(evaluate(IMPORT_CONNECTOR, { connector_type: 'EXTERNAL_IMPORT', connector_info: null })).toEqual([]);
    expect(computeIngestionHealthChecks(IMPORT_CONNECTOR, { ...CONTEXT, runtimeData: {} })).toEqual([]);
  });

  it('should pass on a work whose only errors are the ones of its elements: not a failure of the connector', () => {
    expect(evaluate(IMPORT_CONNECTOR, lastWork([{ message: 'Cannot ingest this entity', source: 'bundle element' }]))).toEqual([]);
  });

  it('should pass on a work whose only errors are reported by the connector with a source: not a failed work', () => {
    expect(evaluate(IMPORT_CONNECTOR, lastWork([{ message: 'Traceback: boom', source: 'CONNECTOR' }]))).toEqual([]);
  });

  it('should pass on a work that is not conclusive: the last run left none', () => {
    const state = { ...lastWork([{ message: 'old failure', source: null }]), connector_info: { last_run_datetime: '2026-10-26T12:00:00Z' } };
    expect(evaluate(IMPORT_CONNECTOR, state)).toEqual([]);
  });

  it.each(['EXTERNAL_IMPORT', 'INTERNAL_ENRICHMENT', 'INTERNAL_IMPORT_FILE', 'INTERNAL_EXPORT_FILE'])('should be enabled for a %s connector', (connectorType) => {
    expect(HEALTH_CHECK_REGISTRY[HEALTH_CHECK_LAST_RUN_FAILED].isEnabled({ ...CONNECTOR, connector_type: connectorType }, NOT_PINGING)).toBe(true);
  });

  it('should not be enabled for a stream connector', () => {
    expect(HEALTH_CHECK_REGISTRY[HEALTH_CHECK_LAST_RUN_FAILED].isEnabled({ ...CONNECTOR, connector_type: 'STREAM' }, NOT_PINGING)).toBe(false);
  });

  it('should not be enabled for a feed or a sync', () => {
    const { isEnabled } = HEALTH_CHECK_REGISTRY[HEALTH_CHECK_LAST_RUN_FAILED];
    expect(isEnabled({ ...FEED, last_execution_status: 'error' }, NOT_PINGING)).toBe(false);
    expect(isEnabled({ ...SYNC, last_execution_status: 'error' }, NOT_PINGING)).toBe(false);
  });

  it('should report a 401 as a failed run: the access of a connector is not checked', () => {
    const checks = evaluate(IMPORT_CONNECTOR, lastWork([{ message: '401 Client Error: Unauthorized for url: https://api.example.com/x', source: null }]));
    expect(checks.map((check) => check.health_check_code)).toEqual([HEALTH_CHECK_LAST_RUN_FAILED]);
  });

  it('should not be superseded by any check', () => {
    expect(HEALTH_CHECK_REGISTRY[HEALTH_CHECK_LAST_RUN_FAILED]).not.toHaveProperty('supersededBy');
  });

  it('should make the status degraded (advisory runtime check)', () => {
    const checks = evaluate(IMPORT_CONNECTOR, lastWork([{ message: 'boom', source: null }]));
    const patch = computeIngestionHealthPatch({}, checks, CONTEXT);
    expect(patch?.ingestion_health?.status).toBe(IngestionHealthStatus.Degraded);
    expect(toGraphqlIngestionHealth(patch?.ingestion_health, CONNECTOR.entity_type)?.healthChecks).toEqual([{
      health_check_code: HEALTH_CHECK_LAST_RUN_FAILED,
      health_check_message: 'Last run failed: {error}',
      health_check_metadata: { error: 'boom' },
      health_check_kind: IngestionHealthCheckKind.Runtime,
      health_check_severity: IngestionHealthCheckSeverity.Advisory,
    }]);
  });

  it('should word the message without the error when there is none', () => {
    expect(toGraphqlHealthChecks(failed(), 'Connector')[0].health_check_message).toBe('Last run failed');
  });

  it('should read the state of the connectors with their last work', async () => {
    const state = new Map([[IMPORT_CONNECTOR.internal_id, lastWork([])]]);
    vi.mocked(loadConnectorsRuntimeState).mockResolvedValue(state);
    const read = {} as RuntimeDataReadContext;
    expect(await HEALTH_CHECK_REGISTRY[HEALTH_CHECK_LAST_RUN_FAILED].getRuntimeData([IMPORT_CONNECTOR], read)).toBe(state);
    expect(loadConnectorsRuntimeState).toHaveBeenCalledWith([IMPORT_CONNECTOR], read);
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

describe('disabled health checks', () => {
  // A pinging connector without user nor heartbeat: fails USER_MISSING and HEARTBEAT_MISSING
  const FAILING = { ...CONNECTOR, connector_user_id: null };
  const contextWith = (disabledHealthChecks?: HealthCheckCode[]) => ({ ...CONTEXT, ...PINGING, user: undefined, disabledHealthChecks });

  it('should evaluate every check when none is disabled', () => {
    expect(computeIngestionHealthChecks(FAILING, contextWith())).toEqual([USER_MISSING, HEARTBEAT_MISSING]);
    expect(computeIngestionHealthChecks(FAILING, contextWith([]))).toEqual([USER_MISSING, HEARTBEAT_MISSING]);
  });

  it('should not report a disabled check, even when it fails', () => {
    expect(computeIngestionHealthChecks(FAILING, contextWith([HEALTH_CHECK_HEARTBEAT_MISSING]))).toEqual([USER_MISSING]);
  });

  it('should keep reporting the checks still enabled', () => {
    expect(computeIngestionHealthChecks(FAILING, contextWith([HEALTH_CHECK_USER_MISSING]))).toEqual([HEARTBEAT_MISSING]);
  });

  it('should report nothing when every failing check is disabled', () => {
    expect(computeIngestionHealthChecks(FAILING, contextWith([HEALTH_CHECK_USER_MISSING, HEALTH_CHECK_HEARTBEAT_MISSING]))).toEqual([]);
  });

  it('should drop a failure stored before its check was disabled: the status is computed again without it', () => {
    const current = { ingestion_health: { status: IngestionHealthStatus.Critical, status_since: PREVIOUS_SINCE, health_checks: [USER_MISSING, HEARTBEAT_MISSING] } };
    const context = contextWith([HEALTH_CHECK_HEARTBEAT_MISSING]);
    const patch = computeIngestionHealthPatch(current, computeIngestionHealthChecks(FAILING, context), context);
    expect(patch?.ingestion_health?.health_checks).toEqual([USER_MISSING]);
    expect(patch?.ingestion_health?.status).toBe(IngestionHealthStatus.Degraded);
  });
});

describe('user not service account check', () => {
  const REGULAR_USER = { internal: false, user_service_account: false, hasCapability: () => true };
  const INTERNAL_USER = { internal: true, user_service_account: false, hasCapability: () => true };
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
      health_check_metadata: {},
      health_check_kind: IngestionHealthCheckKind.Configuration,
      health_check_severity: IngestionHealthCheckSeverity.Advisory,
    }]);
  });
});

describe('user missing capability check', () => {
  const WITHOUT_CAPABILITY = { internal: false, user_service_account: true, hasCapability: () => false };
  const checksFor = (ingestor: HealthCheckIngestor, user?: HealthCheckUser) => computeIngestionHealthChecks(ingestor, { ...CONTEXT, ...NOT_PINGING, user });
  const CONNECTOR_WITH_USER = { ...CONNECTOR, connector_user_id: 'user-id' };
  const CONNECTORAPI_DESCRIPTION = 'Connectors API usage: register, ping, export push ...';

  it('should flag a connector whose user lacks CONNECTORAPI, with the description of the capability in the message', () => {
    const checks = checksFor(CONNECTOR_WITH_USER, WITHOUT_CAPABILITY);
    const metadata = { capability: 'CONNECTORAPI', capability_description: CONNECTORAPI_DESCRIPTION };
    expect(checks).toEqual([{ health_check_code: HEALTH_CHECK_USER_MISSING_CAPABILITY, health_check_metadata: metadata }]);
    expect(toGraphqlHealthChecks(checks, CONNECTOR.entity_type)[0].health_check_metadata).toEqual(metadata);
    expect(toGraphqlHealthChecks(checks, CONNECTOR.entity_type)[0].health_check_message).toBe('User lacks required capability: "{capability_description}"');
  });

  it('should ask the user for CONNECTORAPI only', () => {
    const hasCapability = vi.fn(() => true);
    checksFor(CONNECTOR_WITH_USER, { ...SERVICE_ACCOUNT, hasCapability });
    expect(hasCapability).toHaveBeenCalledWith('CONNECTORAPI');
  });

  it('should not flag a connector whose user has the capability', () => {
    expect(checksFor(CONNECTOR_WITH_USER, SERVICE_ACCOUNT)).toEqual([]);
  });

  it('should not judge a feed: no capability is required', () => {
    expect(checksFor({ ...FEED, user_id: 'user-id' }, WITHOUT_CAPABILITY)).toEqual([]);
  });

  it('should not judge an internal user', () => {
    expect(checksFor(CONNECTOR_WITH_USER, { ...WITHOUT_CAPABILITY, internal: true })).toEqual([]);
  });

  it('should not judge a missing user: reported by USER_MISSING only', () => {
    expect(checksFor({ ...CONNECTOR, connector_user_id: 'deleted-user-id' })).toEqual([USER_MISSING]);
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
        health_check_metadata: {},
        health_check_kind: IngestionHealthCheckKind.Configuration,
        health_check_severity: IngestionHealthCheckSeverity.Advisory,
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
  const AFTER_DELAY = at(DEFAULT_HEALTH_NOTIFICATION_DELAY_MS);
  const BEFORE_DELAY = at(DEFAULT_HEALTH_NOTIFICATION_DELAY_MS - 1);
  const { Critical, Degraded, Healthy, Unknown } = IngestionHealthStatus;
  // last_event_status absent: no event published yet
  const health = (status: IngestionHealthStatus, last_event_status?: IngestionHealthStatus, last_event_date = OLD_EVENT): StoredIngestionHealth => (
    { status, status_since: SINCE, health_checks: [], ...(last_event_status ? { last_event_date, last_event_status } : {}) }
  );
  // A health whose event is due once stable: a failure never reported, or an end of failure after a failure reported
  const dueHealth = (status: IngestionHealthStatus) => health(status, status === Critical || status === Degraded ? undefined : Critical);

  it('should return null without health: never evaluated with a status, or stopped', () => {
    expect(computeHealthTransition(undefined, AFTER_DELAY)).toBeNull();
    expect(computeHealthTransition(null, AFTER_DELAY)).toBeNull();
  });

  describe('delay', () => {
    it.each(Object.values(IngestionHealthStatus))('should defer %s inside the delay', (status) => {
      expect(computeHealthTransition(dueHealth(status), SINCE)).toBeNull();
      expect(computeHealthTransition(dueHealth(status), BEFORE_DELAY)).toBeNull();
    });

    it.each(Object.values(IngestionHealthStatus))('should report %s exactly when the delay is elapsed', (status) => {
      expect(computeHealthTransition(dueHealth(status), AFTER_DELAY)).not.toBeNull();
    });
  });

  describe('already notified', () => {
    it.each(Object.values(IngestionHealthStatus))('should not report %s again when the last event published already reports it, even notified at its start with a delay of 0', (status) => {
      expect(computeHealthTransition(health(status, status, SINCE), AFTER_DELAY)).toBeNull();
      expect(computeHealthTransition(health(status, status, SINCE), at(1), 0)).toBeNull();
    });
  });

  describe('configured delay', () => {
    const MINUTE = 60 * 1000;

    it('should report with a delay shorter than the default what the default still defers', () => {
      const evaluatedAt = at(2 * MINUTE);
      expect(computeHealthTransition(health(IngestionHealthStatus.Degraded), evaluatedAt)).toBeNull();
      expect(computeHealthTransition(health(IngestionHealthStatus.Degraded), evaluatedAt, MINUTE)).toBe(HealthTransition.Degraded);
    });

    it('should defer with a delay longer than the default what the default reports', () => {
      expect(computeHealthTransition(health(IngestionHealthStatus.Critical), AFTER_DELAY)).toBe(HealthTransition.Critical);
      expect(computeHealthTransition(health(IngestionHealthStatus.Critical), AFTER_DELAY, 2 * DEFAULT_HEALTH_NOTIFICATION_DELAY_MS)).toBeNull();
    });

    it('should report at the start of the status with a delay of 0', () => {
      expect(computeHealthTransition(health(IngestionHealthStatus.Critical), SINCE, 0)).toBe(HealthTransition.Critical);
    });

    it('should apply the default delay when none is given', () => {
      expect(computeHealthTransition(health(IngestionHealthStatus.Critical), BEFORE_DELAY, undefined)).toBeNull();
      expect(computeHealthTransition(health(IngestionHealthStatus.Critical), AFTER_DELAY, undefined)).toBe(HealthTransition.Critical);
    });
  });

  describe('failure', () => {
    it.each([
      [Critical, HealthTransition.Critical],
      [Degraded, HealthTransition.Degraded],
    ])('should report %s when the last event published is not %s, or when none is', (status, expected) => {
      expect(computeHealthTransition(health(status), AFTER_DELAY)).toBe(expected);
      Object.values(IngestionHealthStatus).filter((lastStatus) => lastStatus !== status).forEach((lastStatus) => {
        expect(computeHealthTransition(health(status, lastStatus), AFTER_DELAY)).toBe(expected);
      });
    });

    it.each([Critical, Degraded])('should not report %s again when the last event published already reports it, whatever its date', (status) => {
      expect(computeHealthTransition(health(status, status, OLD_EVENT), AFTER_DELAY)).toBeNull();
      expect(computeHealthTransition(health(status, status, AFTER_DELAY), at(10 * DEFAULT_HEALTH_NOTIFICATION_DELAY_MS))).toBeNull();
    });
  });

  describe('recovery', () => {
    it.each([
      [Healthy, Critical], [Healthy, Degraded], [Unknown, Critical], [Unknown, Degraded],
    ])('should report a recovery when %s follows a last event published %s', (status, lastStatus) => {
      expect(computeHealthTransition(health(status, lastStatus), AFTER_DELAY)).toBe(HealthTransition.Recovered);
    });

    it.each([Healthy, Unknown])('should not report %s when the last event published is not a failure, or when none is: nothing to recover from', (status) => {
      expect(computeHealthTransition(health(status), AFTER_DELAY)).toBeNull();
      expect(computeHealthTransition(health(status, Healthy), AFTER_DELAY)).toBeNull();
      expect(computeHealthTransition(health(status, Unknown), AFTER_DELAY)).toBeNull();
    });
  });

  describe('markHealthNotified', () => {
    it.each(Object.values(IngestionHealthStatus))('should store the date of the event and the %s status it reports, replacing the previous event', (status) => {
      expect(markHealthNotified(health(status), AFTER_DELAY)).toEqual(health(status, status, AFTER_DELAY));
      expect(markHealthNotified(health(status, Critical, OLD_EVENT), AFTER_DELAY)).toEqual(health(status, status, AFTER_DELAY));
    });
  });

  // Replays periods as the ingestion health manager does, through computeIngestionHealthPatch. Returns the published events.
  describe('scenarios over periods', () => {
    const MINUTE = 60 * 1000;
    const DELAY_MINUTES = DEFAULT_HEALTH_NOTIFICATION_DELAY_MS / MINUTE;
    const checksOf = (status: IngestionHealthStatus): StoredHealthCheck[] => {
      if (status === Critical) return [HEARTBEAT_MISSING];
      if (status === Degraded) return [USER_MISSING];
      return [];
    };
    const run = (steps: [number, IngestionHealthStatus][], notificationDelay = DEFAULT_HEALTH_NOTIFICATION_DELAY_MS) => {
      let current: IngestionHealthFields = {};
      const events: [number, HealthTransition][] = [];
      steps.forEach(([minute, status]) => {
        const evaluatedAt = at(minute * MINUTE);
        // Healthy needs a proof of life: a live heartbeat. Without one and without check, the status is unknown
        const runtimeData = status === Healthy ? { [HEALTH_CHECK_HEARTBEAT_MISSING]: evaluatedAt } : {};
        const patch = computeIngestionHealthPatch(current, checksOf(status), { ...CONTEXT, ...PINGING, evaluatedAt, runtimeData });
        let next = patch ? patch.ingestion_health : current.ingestion_health;
        const transition = computeHealthTransition(next, evaluatedAt, notificationDelay);
        if (transition) {
          events.push([minute, transition]);
          next = next ? markHealthNotified(next, evaluatedAt) : next;
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
      // The last event published is the recovery: unknown, then healthy again, have nothing left to recover from
      expect(run([...minutes(0, 10, Critical), ...minutes(11, 20, Healthy), ...minutes(21, 40, Unknown), ...minutes(41, 60, Healthy)])).toEqual([
        [DELAY_MINUTES, HealthTransition.Critical],
        [11 + DELAY_MINUTES, HealthTransition.Recovered],
      ]);
    });

    it('should not report a failure again after going back to it inside the delay: the last event published already reports it', () => {
      expect(run([...minutes(0, 10, Critical), [11, Healthy], ...minutes(12, 30, Critical)])).toEqual([
        [DELAY_MINUTES, HealthTransition.Critical],
      ]);
      expect(run([...minutes(0, 10, Degraded), ...minutes(11, 12, Critical), ...minutes(13, 30, Degraded)])).toEqual([
        [DELAY_MINUTES, HealthTransition.Degraded],
      ]);
    });

    it('should report the recovery of a failure reported, even when the failure just before the recovery was never reported', () => {
      expect(run([...minutes(0, 10, Degraded), ...minutes(11, 13, Critical), ...minutes(14, 30, Healthy)])).toEqual([
        [DELAY_MINUTES, HealthTransition.Degraded],
        [14 + DELAY_MINUTES, HealthTransition.Recovered],
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

    // Notified in the period the status starts: the event is at its start, and must count as notified at the next periods
    it('should report each status change once at its first period with a delay of 0, and never again while it lasts', () => {
      expect(run([...minutes(0, 10, Degraded), ...minutes(11, 20, Critical), ...minutes(21, 30, Healthy), ...minutes(31, 40, Critical)], 0)).toEqual([
        [0, HealthTransition.Degraded],
        [11, HealthTransition.Critical],
        [21, HealthTransition.Recovered],
        [31, HealthTransition.Critical],
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

  it('should fill the placeholders of the check messages from their metadata', () => {
    const missingCapability = {
      health_check_code: HEALTH_CHECK_USER_MISSING_CAPABILITY,
      health_check_metadata: { capability: 'CONNECTORAPI', capability_description: 'Connectors API usage: register, ping, export push ...' },
    };
    expect(buildHealthTransitionMessage(element, HealthTransition.Critical, [missingCapability]))
      .toBe('reports `My connector` (Connector) as critical: User lacks required capability: "Connectors API usage: register, ping, export push ..."');
  });

  it('should fill the description of a failed execution from its metadata', () => {
    const metadata = { http_status: 404, http_status_text: 'Not Found', failure_description: 'HTTP 404 Not Found' };
    const executionFailed = { health_check_code: HEALTH_CHECK_FEED_AND_SYNC_EXECUTION_FAILED, health_check_metadata: metadata };
    expect(buildHealthTransitionMessage({ name: 'My feed', entity_type: 'IngestionRss' }, HealthTransition.Critical, [executionFailed]))
      .toBe('reports `My feed` (IngestionRss) as critical: Feed execution failed: HTTP 404 Not Found');
  });
});

describe('formatHealthCheckMessage', () => {
  it('should keep a placeholder without value', () => {
    expect(formatHealthCheckMessage('{known} and {unknown}', { known: 'value' })).toBe('value and {unknown}');
  });
});
