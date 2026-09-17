// Ingestion health — the evaluator's thresholds, read from configuration.
//
// Kept out of `ingestionHealth-types.ts` on purpose: that file imports nothing,
// which is what lets the evaluator be unit-tested without a running platform.
// DEFAULT_THRESHOLDS stays the pure fallback the tests use; this is the one the
// manager and the resolvers pass at runtime.
//
// Both sides must use the SAME object, or the chip in the UI and the alert in
// an email start disagreeing about the same source — the one thing the read-time
// design exists to prevent.

import conf from '../../config/conf';
import { DEFAULT_THRESHOLDS, type IngestionHealthThresholds } from './ingestionHealth-types';

const num = (key: string, fallback: number): number => {
  const value = conf.get(`ingestion_health_manager:${key}`);
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback;
};

// Read once at module load, like every other manager setting in the platform.
export const INGESTION_HEALTH_THRESHOLDS: IngestionHealthThresholds = {
  missedPeriodsBeforeAlert: num('missed_periods_before_alert', DEFAULT_THRESHOLDS.missedPeriodsBeforeAlert),
  emptyRunsBeforeAlert: num('empty_runs_before_alert', DEFAULT_THRESHOLDS.emptyRunsBeforeAlert),
  heartbeatGraceSeconds: num('heartbeat_grace_seconds', DEFAULT_THRESHOLDS.heartbeatGraceSeconds),
  // Derived from the manager's own cadence rather than configured separately:
  // two settings that must agree is one setting that will eventually disagree.
  evaluationIntervalSeconds: Math.max(1, Math.round(num('interval', 60000) / 1000)),
  unscheduledStaleSeconds: num('unscheduled_stale_seconds', DEFAULT_THRESHOLDS.unscheduledStaleSeconds),
  restartDeltaThreshold: num('restart_delta_threshold', DEFAULT_THRESHOLDS.restartDeltaThreshold),
  restartDeltaWindowSeconds: num('restart_delta_window_seconds', DEFAULT_THRESHOLDS.restartDeltaWindowSeconds),
  tokenExpiryWarningDays: num('token_expiry_warning_days', DEFAULT_THRESHOLDS.tokenExpiryWarningDays),
};
