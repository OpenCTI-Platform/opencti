import { describe, expect, it } from 'vitest';
import { computeIngestionHealthPatch, HEALTH_CHECK_USER_MISSING } from '../../../../src/modules/ingestionHealth/ingestionHealth-checks';
import { IngestionHealthStatus } from '../../../../src/generated/graphql';
import type { StoredHealthCheck } from '../../../../src/modules/ingestionHealth/ingestionHealth-types';

const EVALUATED_AT = '2026-10-13T12:00:00.000Z';
const PREVIOUS_SINCE = '2026-10-12T08:00:00.000Z';
const USER_MISSING: StoredHealthCheck = { health_check_code: HEALTH_CHECK_USER_MISSING, health_check_metadata: {} };
// Not in the registry: never changes the status
const OTHER_CHECK: StoredHealthCheck = { health_check_code: 'OTHER_CHECK', health_check_metadata: {} };

describe('computeIngestionHealthPatch', () => {
  it('should write unknown with no check and set since on the first evaluation', () => {
    const patch = computeIngestionHealthPatch({}, [], EVALUATED_AT);
    expect(patch).toEqual({
      health_status: IngestionHealthStatus.Unknown,
      health_checks: [],
      health_status_since: EVALUATED_AT,
    });
  });

  it('should write degraded with the check and set since when the user is missing on the first evaluation', () => {
    const patch = computeIngestionHealthPatch({}, [USER_MISSING], EVALUATED_AT);
    expect(patch).toEqual({
      health_status: IngestionHealthStatus.Degraded,
      health_checks: [USER_MISSING],
      health_status_since: EVALUATED_AT,
    });
  });

  it('should return null when neither the status nor the checks changed', () => {
    const current = { health_status: IngestionHealthStatus.Degraded, health_status_since: PREVIOUS_SINCE, health_checks: [USER_MISSING] };
    expect(computeIngestionHealthPatch(current, [USER_MISSING], EVALUATED_AT)).toBeNull();
  });

  it('should return null when no check is stored and none is found', () => {
    const current = { health_status: IngestionHealthStatus.Unknown, health_status_since: PREVIOUS_SINCE, health_checks: [] };
    expect(computeIngestionHealthPatch(current, [], EVALUATED_AT)).toBeNull();
  });

  it('should ignore the order of the checks', () => {
    const current = { health_status: IngestionHealthStatus.Degraded, health_status_since: PREVIOUS_SINCE, health_checks: [OTHER_CHECK, USER_MISSING] };
    expect(computeIngestionHealthPatch(current, [USER_MISSING, OTHER_CHECK], EVALUATED_AT)).toBeNull();
  });

  it('should treat a stored check without metadata as a check with empty metadata', () => {
    const storedWithoutMetadata = { health_check_code: HEALTH_CHECK_USER_MISSING } as StoredHealthCheck;
    const current = { health_status: IngestionHealthStatus.Degraded, health_status_since: PREVIOUS_SINCE, health_checks: [storedWithoutMetadata] };
    expect(computeIngestionHealthPatch(current, [USER_MISSING], EVALUATED_AT)).toBeNull();
  });

  it('should write the checks but keep since when only the checks changed', () => {
    const current = { health_status: IngestionHealthStatus.Degraded, health_status_since: PREVIOUS_SINCE, health_checks: [USER_MISSING] };
    const patch = computeIngestionHealthPatch(current, [USER_MISSING, OTHER_CHECK], EVALUATED_AT);
    expect(patch).toEqual({
      health_status: IngestionHealthStatus.Degraded,
      health_checks: [OTHER_CHECK, USER_MISSING],
    });
  });

  it('should write the checks but keep since when only the metadata changed', () => {
    const current = { health_status: IngestionHealthStatus.Degraded, health_status_since: PREVIOUS_SINCE, health_checks: [USER_MISSING] };
    const changedMetadata = { health_check_code: HEALTH_CHECK_USER_MISSING, health_check_metadata: { log: 'new log' } };
    const patch = computeIngestionHealthPatch(current, [changedMetadata], EVALUATED_AT);
    expect(patch).toEqual({
      health_status: IngestionHealthStatus.Degraded,
      health_checks: [changedMetadata],
    });
  });

  it('should move since when the status changes', () => {
    // The user was fixed: degraded -> unknown
    const current = { health_status: IngestionHealthStatus.Degraded, health_status_since: PREVIOUS_SINCE, health_checks: [USER_MISSING] };
    const patch = computeIngestionHealthPatch(current, [], EVALUATED_AT);
    expect(patch).toEqual({
      health_status: IngestionHealthStatus.Unknown,
      health_checks: [],
      health_status_since: EVALUATED_AT,
    });
  });

  it('should return the checks sorted by code', () => {
    const patch = computeIngestionHealthPatch({}, [USER_MISSING, OTHER_CHECK], EVALUATED_AT);
    expect(patch?.health_checks?.map((check) => check.health_check_code)).toEqual([OTHER_CHECK.health_check_code, HEALTH_CHECK_USER_MISSING]);
  });
});
