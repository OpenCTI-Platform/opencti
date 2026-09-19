import { describe, expect, it } from 'vitest';
import { resolveStaleRunningThresholdMs } from '../../../../src/modules/dataSanity/dataSanity-domain';

const DEFAULT_STALE_RUNNING_THRESHOLD_MS = 86400000; // 24 hours

describe('resolveStaleRunningThresholdMs', () => {
  it('should keep a valid numeric configuration', () => {
    expect(resolveStaleRunningThresholdMs(3600000)).toBe(3600000);
  });

  it('should coerce a numeric string configuration', () => {
    expect(resolveStaleRunningThresholdMs('3600000')).toBe(3600000);
  });

  it('should fall back to the default when no configuration is provided', () => {
    expect(resolveStaleRunningThresholdMs(undefined)).toBe(DEFAULT_STALE_RUNNING_THRESHOLD_MS);
    expect(resolveStaleRunningThresholdMs(null)).toBe(DEFAULT_STALE_RUNNING_THRESHOLD_MS);
    expect(resolveStaleRunningThresholdMs('')).toBe(DEFAULT_STALE_RUNNING_THRESHOLD_MS);
  });

  it('should fall back to the default when the configuration is not a finite positive number', () => {
    expect(resolveStaleRunningThresholdMs('not-a-number')).toBe(DEFAULT_STALE_RUNNING_THRESHOLD_MS);
    expect(resolveStaleRunningThresholdMs(Number.NaN)).toBe(DEFAULT_STALE_RUNNING_THRESHOLD_MS);
    expect(resolveStaleRunningThresholdMs(Number.POSITIVE_INFINITY)).toBe(DEFAULT_STALE_RUNNING_THRESHOLD_MS);
    expect(resolveStaleRunningThresholdMs(0)).toBe(DEFAULT_STALE_RUNNING_THRESHOLD_MS);
    expect(resolveStaleRunningThresholdMs(-1000)).toBe(DEFAULT_STALE_RUNNING_THRESHOLD_MS);
  });
});
