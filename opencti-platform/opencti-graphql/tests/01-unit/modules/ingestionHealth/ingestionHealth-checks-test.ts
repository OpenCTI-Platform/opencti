import { describe, expect, it } from 'vitest';
import {
  buildHealthTransitionMessage,
  computeHealthTransition,
  computeIngestionHealthChecks,
  computeIngestionHealthPatch,
  HEALTH_CHECK_HEARTBEAT_MISSING,
  HEALTH_CHECK_USER_MISSING,
  HealthTransition,
  toGraphqlIngestionHealth,
} from '../../../../src/modules/ingestionHealth/ingestionHealth-checks';
import { CONNECTOR_LIVELINESS_GRACE_PERIOD_MS } from '../../../../src/modules/connector/connector-types';
import { utcDate } from '../../../../src/utils/format';
import { IngestionHealthCheckKind, IngestionHealthCheckSeverity, IngestionHealthStatus } from '../../../../src/generated/graphql';
import type { StoredHealthCheck } from '../../../../src/modules/ingestionHealth/ingestionHealth-types';

const EVALUATED_AT = '2026-10-13T12:00:00.000Z';
const PREVIOUS_SINCE = '2026-10-12T08:00:00.000Z';
const CONTEXT = { evaluatedAt: EVALUATED_AT };
const USER_MISSING: StoredHealthCheck = { health_check_code: HEALTH_CHECK_USER_MISSING, health_check_metadata: {} };
const HEARTBEAT_MISSING: StoredHealthCheck = { health_check_code: HEALTH_CHECK_HEARTBEAT_MISSING, health_check_metadata: {} };
// Not in the registry: never changes the status
const OTHER_CHECK: StoredHealthCheck = { health_check_code: 'OTHER_CHECK', health_check_metadata: {} };

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
    const changedMetadata = { health_check_code: HEALTH_CHECK_USER_MISSING, health_check_metadata: { log: 'new log' } };
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
  const ALIVE = { ...CONTEXT, runtimeData: { heartbeat: EVALUATED_AT } };

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
    expect(computeIngestionHealthPatch({}, [], { ...CONTEXT, runtimeData: { heartbeat } })).toBeNull();
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
  const input = { userId: 'user', isUserRequired: true, isHeartbeatRequired: true };

  it('should flag a missing heartbeat when the source reports one', () => {
    expect(computeIngestionHealthChecks(input, { ...CONTEXT, isExistingUser })).toEqual([HEARTBEAT_MISSING]);
    expect(computeIngestionHealthChecks(input, { ...CONTEXT, runtimeData: {}, isExistingUser })).toEqual([HEARTBEAT_MISSING]);
  });

  it('should not flag a heartbeat that is there', () => {
    expect(computeIngestionHealthChecks(input, { ...CONTEXT, runtimeData: { heartbeat: EVALUATED_AT }, isExistingUser })).toEqual([]);
  });

  it('should not flag a heartbeat younger than the max age', () => {
    const heartbeat = utcDate(EVALUATED_AT).subtract(CONNECTOR_LIVELINESS_GRACE_PERIOD_MS - 1000, 'ms').toISOString();
    expect(computeIngestionHealthChecks(input, { ...CONTEXT, runtimeData: { heartbeat }, isExistingUser })).toEqual([]);
  });

  it('should flag a heartbeat older than the max age as missing', () => {
    const heartbeat = utcDate(EVALUATED_AT).subtract(CONNECTOR_LIVELINESS_GRACE_PERIOD_MS, 'ms').toISOString();
    expect(computeIngestionHealthChecks(input, { ...CONTEXT, runtimeData: { heartbeat }, isExistingUser })).toEqual([HEARTBEAT_MISSING]);
  });

  it('should not flag a heartbeat in the future, clock skew between nodes', () => {
    const heartbeat = utcDate(EVALUATED_AT).add(10_000, 'ms').toISOString();
    expect(computeIngestionHealthChecks(input, { ...CONTEXT, runtimeData: { heartbeat }, isExistingUser })).toEqual([]);
  });

  it('should not flag sources without heartbeat, such as feeds and syncs', () => {
    expect(computeIngestionHealthChecks({ ...input, isHeartbeatRequired: false }, { ...CONTEXT, isExistingUser })).toEqual([]);
  });

  it('should give a critical status with the check message', () => {
    const patch = computeIngestionHealthPatch({}, computeIngestionHealthChecks(input, { ...CONTEXT, isExistingUser }), CONTEXT);
    expect(patch?.ingestion_health?.status).toBe(IngestionHealthStatus.Critical);
    expect(toGraphqlIngestionHealth(patch?.ingestion_health)?.healthChecks).toEqual([{
      health_check_code: HEALTH_CHECK_HEARTBEAT_MISSING,
      health_check_message: 'No heartbeat received',
      health_check_kind: IngestionHealthCheckKind.Runtime,
      health_check_severity: IngestionHealthCheckSeverity.Blocking,
    }]);
  });
});

describe('computeIngestionHealthChecks', () => {
  const EXISTING_USER_ID = 'existing-user-id';
  const DELETED_USER_ID = 'deleted-user-id';
  const isExistingUser = (userId: string) => userId === EXISTING_USER_ID;

  describe('connector (user required)', () => {
    it.each([undefined, null, ''])('should flag USER_MISSING when the user is %s', (userId) => {
      expect(computeIngestionHealthChecks({ userId, isUserRequired: true }, { ...CONTEXT, isExistingUser })).toEqual([USER_MISSING]);
    });

    it('should flag USER_MISSING when the user was deleted', () => {
      expect(computeIngestionHealthChecks({ userId: DELETED_USER_ID, isUserRequired: true }, { ...CONTEXT, isExistingUser })).toEqual([USER_MISSING]);
    });

    it('should return no check when the user exists', () => {
      expect(computeIngestionHealthChecks({ userId: EXISTING_USER_ID, isUserRequired: true }, { ...CONTEXT, isExistingUser })).toEqual([]);
    });
  });

  describe('feed or sync (user optional: runs as the system user without one)', () => {
    it.each([undefined, null, ''])('should return no check when the user is %s', (userId) => {
      expect(computeIngestionHealthChecks({ userId, isUserRequired: false }, { ...CONTEXT, isExistingUser })).toEqual([]);
    });

    it('should flag USER_MISSING when the user was deleted', () => {
      expect(computeIngestionHealthChecks({ userId: DELETED_USER_ID, isUserRequired: false }, { ...CONTEXT, isExistingUser })).toEqual([USER_MISSING]);
    });

    it('should return no check when the user exists', () => {
      expect(computeIngestionHealthChecks({ userId: EXISTING_USER_ID, isUserRequired: false }, { ...CONTEXT, isExistingUser })).toEqual([]);
    });
  });

  it('should make the status degraded through computeIngestionHealthPatch when the user is missing', () => {
    const checks = computeIngestionHealthChecks({ userId: DELETED_USER_ID, isUserRequired: true }, { ...CONTEXT, isExistingUser });
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
    [IngestionHealthStatus.Stopped, IngestionHealthStatus.Healthy, HealthTransition.Recovered],
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

  it('should return null when the status becomes stopped', () => {
    expect(computeHealthTransition(IngestionHealthStatus.Healthy, IngestionHealthStatus.Stopped)).toBeNull();
  });

  it.each([IngestionHealthStatus.Critical, IngestionHealthStatus.Degraded])('should return recovered when the health is removed after %s', (previous) => {
    expect(computeHealthTransition(previous, undefined)).toBe(HealthTransition.Recovered);
  });

  it.each([IngestionHealthStatus.Healthy, IngestionHealthStatus.Stopped])('should return null when the health is removed after %s: nothing failing to recover from', (previous) => {
    expect(computeHealthTransition(previous, undefined)).toBeNull();
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
