import { afterEach, describe, expect, it } from 'vitest';
import {
  buildHealthTransitionMessage,
  buildIngestionHealthContext,
  computeHealthTransition,
  computeIngestionHealthChecks,
  computeIngestionHealthPatch,
  isRuntimeCheckEnabled,
  HealthTransition,
  toGraphqlHealthChecks,
  toGraphqlIngestionHealth,
} from '../../../../src/modules/ingestionHealth/ingestionHealth-checks';
import { HEALTH_CHECK_HEARTBEAT_MISSING, HEALTH_CHECK_REGISTRY, HEALTH_CHECK_USER_MISSING } from '../../../../src/modules/ingestionHealth/ingestionHealth-registry';
import { CONNECTOR_LIVELINESS_GRACE_PERIOD_MS } from '../../../../src/modules/connector/connector-types';
import { utcDate } from '../../../../src/utils/format';
import { IngestionHealthCheckKind, IngestionHealthCheckSeverity, IngestionHealthStatus } from '../../../../src/generated/graphql';
import type { StoredHealthCheck } from '../../../../src/modules/ingestionHealth/ingestionHealth-types';

const EVALUATED_AT = '2026-10-13T12:00:00.000Z';
const PREVIOUS_SINCE = '2026-10-12T08:00:00.000Z';
const CONTEXT = { evaluatedAt: EVALUATED_AT, pingingConnectorsIds: new Set<string>(), isExistingUser: () => true };
const USER_MISSING: StoredHealthCheck = { health_check_code: HEALTH_CHECK_USER_MISSING, health_check_metadata: {} };
const HEARTBEAT_MISSING: StoredHealthCheck = { health_check_code: HEALTH_CHECK_HEARTBEAT_MISSING, health_check_metadata: {} };
// Not in the registry (stored by another platform version): never changes the status
const OTHER_CHECK: StoredHealthCheck = { health_check_code: 'OTHER_CHECK', health_check_metadata: {} };
const CONNECTOR = { internal_id: 'connector-id', entity_type: 'Connector' };
const FEED = { internal_id: 'feed-id', entity_type: 'IngestionRss' };
const PINGING = { pingingConnectorsIds: new Set([CONNECTOR.internal_id]) };
const NOT_PINGING = { pingingConnectorsIds: new Set<string>() };

describe('computeIngestionHealthPatch', () => {
  it('should write nothing with no check since on the first evaluation', () => {
    const patch = computeIngestionHealthPatch({}, [], CONTEXT);
    expect(patch).toEqual(null);
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

  it('should remove ingestion_health when a status was stored and none can be computed anymore', () => {
    // The user was fixed: degraded -> no status (healthy is not computed yet), absence reads as unknown
    const current = { ingestion_health: { status: IngestionHealthStatus.Degraded, status_since: PREVIOUS_SINCE, health_checks: [USER_MISSING] } };
    expect(computeIngestionHealthPatch(current, [], CONTEXT)).toEqual({ ingestion_health: null });
  });

  it('should write nothing when ingestion_health is already absent and no status can be computed', () => {
    expect(computeIngestionHealthPatch({ ingestion_health: null }, [], CONTEXT)).toBeNull();
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

  it('should stay unknown with no check and no heartbeat', () => {
    expect(computeIngestionHealthPatch({}, [], CONTEXT)).toBeNull();
  });

  it('should not be healthy when a check fails, whatever the heartbeat', () => {
    expect(computeIngestionHealthPatch({}, [USER_MISSING], ALIVE)?.ingestion_health?.status).toBe(IngestionHealthStatus.Degraded);
  });

  it('should not be healthy with a check unknown to this platform version', () => {
    expect(computeIngestionHealthPatch({}, [OTHER_CHECK], ALIVE)).toBeNull();
  });

  it('should go back to unknown when the heartbeat expires', () => {
    const current = { ingestion_health: { status: IngestionHealthStatus.Healthy, status_since: PREVIOUS_SINCE, health_checks: [] } };
    expect(computeIngestionHealthPatch(current, [], CONTEXT)).toEqual({ ingestion_health: null });
  });

  it('should not be healthy on a stale heartbeat', () => {
    const heartbeat = utcDate(EVALUATED_AT).subtract(CONNECTOR_LIVELINESS_GRACE_PERIOD_MS, 'ms').toISOString();
    expect(computeIngestionHealthPatch({}, [], { ...CONTEXT, runtimeData: { [HEALTH_CHECK_HEARTBEAT_MISSING]: heartbeat } })).toBeNull();
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
  const isExistingUser = () => true;
  const input = { ...CONNECTOR, connector_user_id: 'user' };

  it('should flag a missing heartbeat when the source reports one', () => {
    expect(computeIngestionHealthChecks(input, { ...CONTEXT, ...PINGING, isExistingUser })).toEqual([HEARTBEAT_MISSING]);
    expect(computeIngestionHealthChecks(input, { ...CONTEXT, ...PINGING, runtimeData: {}, isExistingUser })).toEqual([HEARTBEAT_MISSING]);
  });

  it('should not flag a heartbeat that is there', () => {
    expect(computeIngestionHealthChecks(input, { ...CONTEXT, ...PINGING, runtimeData: { [HEALTH_CHECK_HEARTBEAT_MISSING]: EVALUATED_AT }, isExistingUser })).toEqual([]);
  });

  it('should not flag a heartbeat younger than the max age', () => {
    const heartbeat = utcDate(EVALUATED_AT).subtract(CONNECTOR_LIVELINESS_GRACE_PERIOD_MS - 1000, 'ms').toISOString();
    expect(computeIngestionHealthChecks(input, { ...CONTEXT, ...PINGING, runtimeData: { [HEALTH_CHECK_HEARTBEAT_MISSING]: heartbeat }, isExistingUser })).toEqual([]);
  });

  it('should flag a heartbeat older than the max age as missing', () => {
    const heartbeat = utcDate(EVALUATED_AT).subtract(CONNECTOR_LIVELINESS_GRACE_PERIOD_MS, 'ms').toISOString();
    const runtimeData = { [HEALTH_CHECK_HEARTBEAT_MISSING]: heartbeat };
    expect(computeIngestionHealthChecks(input, { ...CONTEXT, ...PINGING, runtimeData, isExistingUser })).toEqual([HEARTBEAT_MISSING]);
  });

  it('should not flag a heartbeat in the future, clock skew between nodes', () => {
    const heartbeat = utcDate(EVALUATED_AT).add(10_000, 'ms').toISOString();
    expect(computeIngestionHealthChecks(input, { ...CONTEXT, ...PINGING, runtimeData: { [HEALTH_CHECK_HEARTBEAT_MISSING]: heartbeat }, isExistingUser })).toEqual([]);
  });

  it('should not flag sources without heartbeat, such as feeds and syncs', () => {
    expect(computeIngestionHealthChecks({ ...FEED, user_id: 'user' }, { ...CONTEXT, ...PINGING, isExistingUser })).toEqual([]);
  });

  it('should not flag connectors not pinging continuously, such as run and terminate ones', () => {
    expect(computeIngestionHealthChecks(input, { ...CONTEXT, ...NOT_PINGING, isExistingUser })).toEqual([]);
  });

  it('should not flag built-in connectors', () => {
    expect(computeIngestionHealthChecks({ ...input, built_in: true }, { ...CONTEXT, ...PINGING, isExistingUser })).toEqual([]);
  });

  it('should be healthy with a fresh heartbeat when the connector pings continuously', () => {
    const context = buildIngestionHealthContext(input, { ...CONTEXT, ...PINGING, runtimeData: { [HEALTH_CHECK_HEARTBEAT_MISSING]: EVALUATED_AT } });
    expect(computeIngestionHealthPatch({}, computeIngestionHealthChecks(input, context), context)?.ingestion_health?.status).toBe(IngestionHealthStatus.Healthy);
  });

  it('should give no status with a fresh heartbeat when the connector does not ping continuously, such as after a run and terminate run', () => {
    const context = buildIngestionHealthContext(input, { ...CONTEXT, ...NOT_PINGING, runtimeData: { [HEALTH_CHECK_HEARTBEAT_MISSING]: EVALUATED_AT } });
    expect(computeIngestionHealthPatch({}, computeIngestionHealthChecks(input, context), context)).toBeNull();
  });

  it('should give no status with a fresh heartbeat on a built-in connector', () => {
    const builtIn = { ...input, built_in: true };
    const context = buildIngestionHealthContext(builtIn, { ...CONTEXT, ...PINGING, runtimeData: { [HEALTH_CHECK_HEARTBEAT_MISSING]: EVALUATED_AT } });
    expect(computeIngestionHealthPatch({}, computeIngestionHealthChecks(builtIn, context), context)).toBeNull();
  });

  it('should give a critical status with the check message', () => {
    const patch = computeIngestionHealthPatch({}, computeIngestionHealthChecks(input, { ...CONTEXT, ...PINGING, isExistingUser }), CONTEXT);
    expect(patch?.ingestion_health?.status).toBe(IngestionHealthStatus.Critical);
    expect(toGraphqlIngestionHealth(patch?.ingestion_health)?.healthChecks).toEqual([{
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

  it('should be false for a built-in connector', () => {
    expect(isRuntimeCheckEnabled({ ...CONNECTOR, built_in: true }, { ...CONTEXT, ...PINGING })).toBe(false);
  });

  it('should be false for feeds and syncs, which have no runtime check', () => {
    expect(isRuntimeCheckEnabled(FEED, { ...CONTEXT, ...PINGING })).toBe(false);
  });
});

describe('check metadata', () => {
  const TEST_CODE = 'TEST_CHECK';
  const registry = HEALTH_CHECK_REGISTRY as Record<string, unknown>;
  const checksContext = { ...CONTEXT, ...NOT_PINGING, isExistingUser: () => true };
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
    expect(toGraphqlHealthChecks(checks).find((check) => check.health_check_code === TEST_CODE)?.health_check_message).toBe('Failing for test');
  });

  it('should not store a check that passes', () => {
    failWith(null);
    expect(computeIngestionHealthChecks(CONNECTOR, checksContext).map((check) => check.health_check_code)).not.toContain(TEST_CODE);
  });
});

describe('computeIngestionHealthChecks', () => {
  const EXISTING_USER_ID = 'existing-user-id';
  const DELETED_USER_ID = 'deleted-user-id';
  const isExistingUser = (userId: string) => userId === EXISTING_USER_ID;
  const checksContext = { ...CONTEXT, ...NOT_PINGING, isExistingUser };

  describe('connector (user required)', () => {
    it.each([undefined, null, ''])('should flag USER_MISSING when the user is %s', (userId) => {
      expect(computeIngestionHealthChecks({ ...CONNECTOR, connector_user_id: userId }, checksContext)).toEqual([USER_MISSING]);
    });

    it('should flag USER_MISSING when the user was deleted', () => {
      expect(computeIngestionHealthChecks({ ...CONNECTOR, connector_user_id: DELETED_USER_ID }, checksContext)).toEqual([USER_MISSING]);
    });

    it('should return no check when the user exists', () => {
      expect(computeIngestionHealthChecks({ ...CONNECTOR, connector_user_id: EXISTING_USER_ID }, checksContext)).toEqual([]);
    });
  });

  describe('feed or sync (user optional: runs as the system user without one)', () => {
    it.each([undefined, null, ''])('should return no check when the user is %s', (userId) => {
      expect(computeIngestionHealthChecks({ ...FEED, user_id: userId }, checksContext)).toEqual([]);
    });

    it('should flag USER_MISSING when the user was deleted', () => {
      expect(computeIngestionHealthChecks({ ...FEED, user_id: DELETED_USER_ID }, checksContext)).toEqual([USER_MISSING]);
    });

    it('should return no check when the user exists', () => {
      expect(computeIngestionHealthChecks({ ...FEED, user_id: EXISTING_USER_ID }, checksContext)).toEqual([]);
    });
  });

  it('should not flag USER_MISSING on built-in connectors', () => {
    expect(computeIngestionHealthChecks({ ...CONNECTOR, built_in: true, connector_user_id: DELETED_USER_ID }, checksContext)).toEqual([]);
  });

  it('should make the status degraded through computeIngestionHealthPatch when the user is missing', () => {
    const checks = computeIngestionHealthChecks({ ...CONNECTOR, connector_user_id: DELETED_USER_ID }, checksContext);
    expect(computeIngestionHealthPatch({}, checks, CONTEXT)?.ingestion_health?.status).toBe(IngestionHealthStatus.Degraded);
  });
});

describe('toGraphqlIngestionHealth', () => {
  it('should return null when the ingestion was never evaluated', () => {
    expect(toGraphqlIngestionHealth(undefined)).toBeNull();
  });

  it('should expose status and since, and the checks enriched from the registry', () => {
    const health = { status: IngestionHealthStatus.Degraded, status_since: PREVIOUS_SINCE, health_checks: [USER_MISSING] };
    expect(toGraphqlIngestionHealth(health)).toEqual({
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
    expect(toGraphqlIngestionHealth({ status: IngestionHealthStatus.Healthy, status_since: PREVIOUS_SINCE, health_checks: [OTHER_CHECK] })?.healthChecks).toEqual([]);
    expect(toGraphqlIngestionHealth({ status: IngestionHealthStatus.Healthy, status_since: PREVIOUS_SINCE })?.healthChecks).toEqual([]);
  });
});

describe('computeHealthTransition', () => {
  it.each([
    [IngestionHealthStatus.Healthy, IngestionHealthStatus.Critical, HealthTransition.Critical],
    [IngestionHealthStatus.Degraded, IngestionHealthStatus.Critical, HealthTransition.Critical],
    [IngestionHealthStatus.Healthy, IngestionHealthStatus.Degraded, HealthTransition.Degraded],
    [IngestionHealthStatus.Critical, IngestionHealthStatus.Degraded, HealthTransition.Degraded],
    [IngestionHealthStatus.Degraded, IngestionHealthStatus.Healthy, HealthTransition.Recovered],
    [IngestionHealthStatus.Critical, IngestionHealthStatus.Healthy, HealthTransition.Recovered],
  ])('should return the transition from %s to %s', (previous, next, expected) => {
    expect(computeHealthTransition(previous, next)).toBe(expected);
  });

  it.each(Object.values(IngestionHealthStatus))('should return null when the status stays %s', (status) => {
    expect(computeHealthTransition(status, status)).toBeNull();
  });

  it('should return the transition on the first evaluation of a failing ingestion', () => {
    expect(computeHealthTransition(undefined, IngestionHealthStatus.Critical)).toBe(HealthTransition.Critical);
    expect(computeHealthTransition(undefined, IngestionHealthStatus.Degraded)).toBe(HealthTransition.Degraded);
  });

  it('should return null on the first evaluation of a healthy ingestion: nothing recovered', () => {
    expect(computeHealthTransition(undefined, IngestionHealthStatus.Healthy)).toBeNull();
  });

  it.each([IngestionHealthStatus.Critical, IngestionHealthStatus.Degraded])('should return recovered when the health is removed after %s', (previous) => {
    expect(computeHealthTransition(previous, undefined)).toBe(HealthTransition.Recovered);
  });

  it('should return null when the health is removed after healthy: nothing failing to recover from', () => {
    expect(computeHealthTransition(IngestionHealthStatus.Healthy, undefined)).toBeNull();
  });

  it('should return null when there is no health before and after', () => {
    expect(computeHealthTransition(undefined, undefined)).toBeNull();
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
