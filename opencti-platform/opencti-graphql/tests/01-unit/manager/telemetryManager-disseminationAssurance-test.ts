import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { logApp } from '../../../src/config/conf';
import { redisSetTelemetryAdd } from '../../../src/database/redis';
import {
  addIndicatorDeploymentReportCount,
  addIndicatorHitsReportCount,
  addIocValidationPlatformResultCount,
  addIocValidationRequestCreationCount,
  TELEMETRY_GAUGE_INDICATOR_DEPLOYMENT_REPORT,
  TELEMETRY_GAUGE_INDICATOR_HITS_REPORT,
  TELEMETRY_GAUGE_IOC_VALIDATION_PLATFORM_RESULT,
  TELEMETRY_GAUGE_IOC_VALIDATION_REQUEST_CREATION,
} from '../../../src/manager/telemetryManager';

vi.mock('../../../src/database/redis', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/database/redis')>();
  return {
    ...actual,
    redisSetTelemetryAdd: vi.fn(),
  };
});

describe('Dissemination assurance telemetry counters', () => {
  beforeEach(() => {
    vi.mocked(redisSetTelemetryAdd).mockReset();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should count the reports, the requests and the results', () => {
    vi.mocked(redisSetTelemetryAdd).mockResolvedValue(undefined);
    addIndicatorDeploymentReportCount(3);
    addIndicatorHitsReportCount(2);
    addIocValidationRequestCreationCount();
    addIocValidationPlatformResultCount(4);
    expect(vi.mocked(redisSetTelemetryAdd).mock.calls).toEqual([
      [TELEMETRY_GAUGE_INDICATOR_DEPLOYMENT_REPORT, 3],
      [TELEMETRY_GAUGE_INDICATOR_HITS_REPORT, 2],
      [TELEMETRY_GAUGE_IOC_VALIDATION_REQUEST_CREATION, 1],
      [TELEMETRY_GAUGE_IOC_VALIDATION_PLATFORM_RESULT, 4],
    ]);
  });

  it('should never fail the operation they count when the telemetry write fails, only log it', async () => {
    const failure = new Error('Redis unavailable');
    vi.mocked(redisSetTelemetryAdd).mockRejectedValue(failure);
    const logAppWarnSpy = vi.spyOn(logApp, 'warn');
    expect(() => {
      addIndicatorDeploymentReportCount(3);
      addIndicatorHitsReportCount(2);
      addIocValidationRequestCreationCount();
      addIocValidationPlatformResultCount(4);
    }).not.toThrow();
    await vi.waitFor(() => expect(logAppWarnSpy).toHaveBeenCalledTimes(4));
    expect(logAppWarnSpy.mock.calls.map(([, meta]) => meta)).toEqual(Array(4).fill({ cause: failure }));
  });
});
