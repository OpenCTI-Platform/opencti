import { describe, expect, it } from 'vitest';
import {
  computeIngestionHealthChecks,
  computeIngestionHealthPatch,
  HEALTH_CHECK_USER_MISSING,
  toGraphqlIngestionHealth,
} from '../../../../src/modules/ingestionHealth/ingestionHealth-checks';
import { IngestionHealthCheckKind, IngestionHealthCheckSeverity, IngestionHealthStatus } from '../../../../src/generated/graphql';
import type { StoredHealthCheck } from '../../../../src/modules/ingestionHealth/ingestionHealth-types';

const EVALUATED_AT = '2026-10-13T12:00:00.000Z';
const PREVIOUS_SINCE = '2026-10-12T08:00:00.000Z';
const USER_MISSING: StoredHealthCheck = { health_check_code: HEALTH_CHECK_USER_MISSING, health_check_metadata: {} };
// Not in the registry: never changes the status
const OTHER_CHECK: StoredHealthCheck = { health_check_code: 'OTHER_CHECK', health_check_metadata: {} };

describe('computeIngestionHealthPatch', () => {
  it('should write nothing with no check since on the first evaluation', () => {
    const patch = computeIngestionHealthPatch({}, [], EVALUATED_AT);
    expect(patch).toEqual(null);
  });

  it('should write degraded with the check and set since when the user is missing on the first evaluation', () => {
    const patch = computeIngestionHealthPatch({}, [USER_MISSING], EVALUATED_AT);
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
    expect(computeIngestionHealthPatch(current, [USER_MISSING], EVALUATED_AT)).toBeNull();
  });

  it('should remove ingestion_health when a status was stored and none can be computed anymore', () => {
    // The user was fixed: degraded -> no status (healthy is not computed yet), absence reads as unknown
    const current = { ingestion_health: { status: IngestionHealthStatus.Degraded, status_since: PREVIOUS_SINCE, health_checks: [USER_MISSING] } };
    expect(computeIngestionHealthPatch(current, [], EVALUATED_AT)).toEqual({ ingestion_health: null });
  });

  it('should write nothing when ingestion_health is already absent and no status can be computed', () => {
    expect(computeIngestionHealthPatch({ ingestion_health: null }, [], EVALUATED_AT)).toBeNull();
  });

  it('should treat a stored check without metadata as a check with empty metadata', () => {
    const storedWithoutMetadata: StoredHealthCheck = { health_check_code: HEALTH_CHECK_USER_MISSING };
    const current = { ingestion_health: { status: IngestionHealthStatus.Degraded, status_since: PREVIOUS_SINCE, health_checks: [storedWithoutMetadata] } };
    expect(computeIngestionHealthPatch(current, [USER_MISSING], EVALUATED_AT)).toBeNull();
  });

  it('should write the checks but keep since when only the metadata changed', () => {
    const current = { ingestion_health: { status: IngestionHealthStatus.Degraded, status_since: PREVIOUS_SINCE, health_checks: [USER_MISSING] } };
    const changedMetadata = { health_check_code: HEALTH_CHECK_USER_MISSING, health_check_metadata: { log: 'new log' } };
    const patch = computeIngestionHealthPatch(current, [changedMetadata], EVALUATED_AT);
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
    const patch = computeIngestionHealthPatch(current, [USER_MISSING], EVALUATED_AT);
    expect(patch).toEqual({
      ingestion_health: {
        status: IngestionHealthStatus.Degraded,
        health_checks: [USER_MISSING],
        status_since: EVALUATED_AT,
      },
    });
  });
});

describe('computeIngestionHealthChecks', () => {
  const EXISTING_USER_ID = 'existing-user-id';
  const DELETED_USER_ID = 'deleted-user-id';
  const isExistingUser = (userId: string) => userId === EXISTING_USER_ID;

  describe('connector (user required)', () => {
    it.each([undefined, null, ''])('should flag USER_MISSING when the user is %s', (userId) => {
      expect(computeIngestionHealthChecks({ userId, isUserRequired: true }, isExistingUser)).toEqual([USER_MISSING]);
    });

    it('should flag USER_MISSING when the user was deleted', () => {
      expect(computeIngestionHealthChecks({ userId: DELETED_USER_ID, isUserRequired: true }, isExistingUser)).toEqual([USER_MISSING]);
    });

    it('should return no check when the user exists', () => {
      expect(computeIngestionHealthChecks({ userId: EXISTING_USER_ID, isUserRequired: true }, isExistingUser)).toEqual([]);
    });
  });

  describe('feed or sync (user optional: runs as the system user without one)', () => {
    it.each([undefined, null, ''])('should return no check when the user is %s', (userId) => {
      expect(computeIngestionHealthChecks({ userId, isUserRequired: false }, isExistingUser)).toEqual([]);
    });

    it('should flag USER_MISSING when the user was deleted', () => {
      expect(computeIngestionHealthChecks({ userId: DELETED_USER_ID, isUserRequired: false }, isExistingUser)).toEqual([USER_MISSING]);
    });

    it('should return no check when the user exists', () => {
      expect(computeIngestionHealthChecks({ userId: EXISTING_USER_ID, isUserRequired: false }, isExistingUser)).toEqual([]);
    });
  });

  it('should make the status degraded through computeIngestionHealthPatch when the user is missing', () => {
    const checks = computeIngestionHealthChecks({ userId: DELETED_USER_ID, isUserRequired: true }, isExistingUser);
    expect(computeIngestionHealthPatch({}, checks, EVALUATED_AT)?.ingestion_health?.status).toBe(IngestionHealthStatus.Degraded);
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
