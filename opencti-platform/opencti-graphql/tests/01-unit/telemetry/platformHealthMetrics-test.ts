import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { logApp } from '../../../src/config/conf';
import { isEngineAlive } from '../../../src/database/engine';
import { isStorageAlive } from '../../../src/database/raw-file-storage';
import { rabbitMQIsAlive } from '../../../src/database/rabbitmq';
import {
  adoptSharedUsageMetrics,
  buildHealthFailures,
  type DependencyStatus,
  getPlatformHealthStatus,
  getPlatformUsageMetrics,
  type HealthDependency,
  parseCachedUsageMetrics,
  refreshDependencyStatus,
  startPlatformHealthMonitor,
  stopPlatformHealthMonitor,
} from '../../../src/telemetry/platformHealthMetrics';
import { redisGetPlatformUsageMetrics, redisIsAlive } from '../../../src/database/redis';

vi.mock('../../../src/database/redis', () => ({
  redisGetPlatformUsageMetrics: vi.fn(),
  redisIsAlive: vi.fn(),
}));
vi.mock('../../../src/database/engine', () => ({ isEngineAlive: vi.fn() }));
vi.mock('../../../src/database/raw-file-storage', () => ({ isStorageAlive: vi.fn() }));
vi.mock('../../../src/database/rabbitmq', () => ({ rabbitMQIsAlive: vi.fn() }));

const buildStatuses = (overrides: Partial<Record<HealthDependency, DependencyStatus>> = {}): Record<HealthDependency, DependencyStatus> => {
  const alive: DependencyStatus = { isAlive: true, error: null, checkedAt: 1 };
  return {
    elasticsearch: alive,
    storage: alive,
    rabbitmq: alive,
    redis: alive,
    ...overrides,
  };
};

describe('platformHealthMetrics: buildHealthFailures function', () => {
  it('should return no failure when every dependency is alive', () => {
    expect(buildHealthFailures(buildStatuses())).toEqual([]);
  });

  it('should report a failing dependency with its error message', () => {
    const statuses = buildStatuses({ redis: { isAlive: false, error: 'Redis seems down', checkedAt: 1 } });

    expect(buildHealthFailures(statuses)).toEqual(['redis: Redis seems down']);
  });

  it('should report every failing dependency', () => {
    const statuses = buildStatuses({
      redis: { isAlive: false, error: 'Redis seems down', checkedAt: 1 },
      rabbitmq: { isAlive: false, error: 'RabbitMQ seems down', checkedAt: 1 },
    });

    expect(buildHealthFailures(statuses)).toEqual(['rabbitmq: RabbitMQ seems down', 'redis: Redis seems down']);
  });

  it('should fall back to a generic message when no error was captured', () => {
    const statuses = buildStatuses({ storage: { isAlive: false, error: null, checkedAt: 1 } });

    expect(buildHealthFailures(statuses)).toEqual(['storage: unavailable']);
  });

  it('should not report dependencies that have never been checked', () => {
    const statuses = buildStatuses({ elasticsearch: { isAlive: false, error: null, checkedAt: null } });

    expect(buildHealthFailures(statuses)).toEqual([]);
  });
});

describe('platformHealthMetrics: parseCachedUsageMetrics function', () => {
  it('should adopt a payload shared by another node', () => {
    const cached = { es_used_size: 10, s3_used_size: 20, queue_consumers: { EXTERNAL_IMPORT: 3 } };

    expect(parseCachedUsageMetrics(cached)).toEqual(cached);
  });

  it('should adopt a payload where a metric could not be collected', () => {
    const cached = { es_used_size: null, s3_used_size: 20, queue_consumers: null };

    expect(parseCachedUsageMetrics(cached)).toEqual(cached);
  });

  it('should ignore an empty cache', () => {
    expect(parseCachedUsageMetrics(null)).toBeNull();
  });

  it('should ignore a payload whose sizes are not numbers', () => {
    expect(parseCachedUsageMetrics({ es_used_size: '10', s3_used_size: 20, queue_consumers: null })).toBeNull();
    expect(parseCachedUsageMetrics({ es_used_size: 10, queue_consumers: null })).toBeNull();
  });

  it('should ignore a payload whose consumer counts are not numbers', () => {
    const cached = { es_used_size: 10, s3_used_size: 20, queue_consumers: { EXTERNAL_IMPORT: 'many' } };

    expect(parseCachedUsageMetrics(cached)).toBeNull();
  });
});

describe('platformHealthMetrics: adoptSharedUsageMetrics function', () => {
  const shared = { es_used_size: 10, s3_used_size: 20, queue_consumers: { EXTERNAL_IMPORT: 3 } };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should adopt the value shared by the manager through Redis', async () => {
    vi.mocked(redisGetPlatformUsageMetrics).mockResolvedValue(shared);

    await adoptSharedUsageMetrics();

    expect(getPlatformUsageMetrics()).toEqual(shared);
  });

  it('should reset metrics when nothing has been published yet', async () => {
    vi.mocked(redisGetPlatformUsageMetrics).mockResolvedValue(shared);
    await adoptSharedUsageMetrics();

    vi.mocked(redisGetPlatformUsageMetrics).mockResolvedValue(null);
    await adoptSharedUsageMetrics();

    expect(getPlatformUsageMetrics()).toEqual({ es_used_size: null, s3_used_size: null, queue_consumers: null });
  });

  it('should reset metrics when the published payload is invalid', async () => {
    vi.mocked(redisGetPlatformUsageMetrics).mockResolvedValue(shared);
    await adoptSharedUsageMetrics();

    vi.mocked(redisGetPlatformUsageMetrics).mockResolvedValue({ es_used_size: 'nope' });
    await adoptSharedUsageMetrics();

    expect(getPlatformUsageMetrics()).toEqual({ es_used_size: null, s3_used_size: null, queue_consumers: null });
  });
});

describe('platformHealthMetrics: getPlatformHealthStatus function', () => {
  beforeEach(() => {
    stopPlatformHealthMonitor();
    vi.clearAllMocks();
  });

  it('should expose every dependency state after a refresh', async () => {
    vi.mocked(isEngineAlive).mockResolvedValue(undefined);
    vi.mocked(isStorageAlive).mockRejectedValue(Error('Storage seems down'));
    vi.mocked(rabbitMQIsAlive).mockResolvedValue(true);
    vi.mocked(redisIsAlive).mockResolvedValue(true);

    await refreshDependencyStatus();

    expect(getPlatformHealthStatus()).toEqual({
      initialized: true,
      isHealthy: false,
      failures: ['storage: Storage seems down'],
      dependencies: {
        elasticsearch: true,
        storage: false,
        rabbitmq: true,
        redis: true,
      },
    });
  });
});

describe('platformHealthMetrics: startPlatformHealthMonitor function', () => {
  beforeEach(() => {
    stopPlatformHealthMonitor();
    vi.clearAllMocks();
  });

  it('should keep startup alive when the initial shared usage metrics read fails', async () => {
    vi.mocked(isEngineAlive).mockResolvedValue(undefined);
    vi.mocked(isStorageAlive).mockResolvedValue(true);
    vi.mocked(rabbitMQIsAlive).mockResolvedValue(true);
    vi.mocked(redisIsAlive).mockResolvedValue(true);
    vi.mocked(redisGetPlatformUsageMetrics).mockRejectedValue(Error('Redis read failed'));
    const errorSpy = vi.spyOn(logApp, 'error').mockImplementation(() => {});

    await expect(startPlatformHealthMonitor()).resolves.toBeUndefined();

    expect(errorSpy).toHaveBeenCalledWith(
      '[HEALTH] Initial usage metrics adoption failed',
      expect.objectContaining({ cause: expect.any(Error) }),
    );
    expect(getPlatformHealthStatus()).toEqual({
      initialized: true,
      isHealthy: true,
      failures: [],
      dependencies: {
        elasticsearch: true,
        storage: true,
        rabbitmq: true,
        redis: true,
      },
    });
    stopPlatformHealthMonitor();
  });
});

describe('platformHealthMetrics: dependency outage logging', () => {
  const CHECK_INTERVAL_MS = 30_000;
  const OUTAGE_START = new Date('2026-01-01T00:00:00.000Z').getTime();
  let errorSpy: ReturnType<typeof vi.spyOn>;
  let warnSpy: ReturnType<typeof vi.spyOn>;
  let infoSpy: ReturnType<typeof vi.spyOn>;
  let debugSpy: ReturnType<typeof vi.spyOn>;

  type LogCall = [message: string, meta?: { dependency?: string; outageDurationMs?: number }];
  const failureLogs = (spy: ReturnType<typeof vi.spyOn>, message: string) => (spy.mock.calls as LogCall[])
    .filter(([logMessage, meta]: LogCall) => logMessage === message && meta?.dependency === 'rabbitmq');

  beforeEach(() => {
    stopPlatformHealthMonitor();
    vi.clearAllMocks();
    vi.useFakeTimers({ now: OUTAGE_START });
    vi.mocked(isEngineAlive).mockResolvedValue(undefined);
    vi.mocked(isStorageAlive).mockResolvedValue(true);
    vi.mocked(rabbitMQIsAlive).mockResolvedValue(true);
    vi.mocked(redisIsAlive).mockResolvedValue(true);
    vi.mocked(redisGetPlatformUsageMetrics).mockResolvedValue(null);
    errorSpy = vi.spyOn(logApp, 'error').mockImplementation(() => {});
    warnSpy = vi.spyOn(logApp, 'warn').mockImplementation(() => {});
    infoSpy = vi.spyOn(logApp, 'info').mockImplementation(() => {});
    debugSpy = vi.spyOn(logApp, 'debug').mockImplementation(() => {});
  });

  afterEach(() => {
    stopPlatformHealthMonitor();
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('should log an error when an alive dependency becomes unreachable', async () => {
    await refreshDependencyStatus();
    expect(errorSpy).not.toHaveBeenCalled();

    vi.mocked(rabbitMQIsAlive).mockRejectedValue(Error('RabbitMQ seems down'));
    await refreshDependencyStatus();

    expect(errorSpy).toHaveBeenCalledTimes(1);
    expect(errorSpy).toHaveBeenCalledWith('[HEALTH] Dependency check failed', { dependency: 'rabbitmq', cause: expect.any(Error) });
  });

  it('should not log an error again while the dependency stays unreachable', async () => {
    vi.mocked(rabbitMQIsAlive).mockRejectedValue(Error('RabbitMQ seems down'));
    await refreshDependencyStatus();

    for (let check = 0; check < 5; check += 1) {
      await vi.advanceTimersByTimeAsync(CHECK_INTERVAL_MS);
      await refreshDependencyStatus();
    }

    expect(errorSpy).toHaveBeenCalledTimes(1);
    expect(warnSpy).not.toHaveBeenCalled();
    expect(failureLogs(debugSpy, '[HEALTH] Dependency check failed')).toHaveLength(5);
    // Every probe is still reported through the health status
    expect(getPlatformHealthStatus().failures).toEqual(['rabbitmq: RabbitMQ seems down']);
  });

  it('should remind with a warning every five minutes while the outage lasts', async () => {
    vi.mocked(rabbitMQIsAlive).mockRejectedValue(Error('RabbitMQ seems down'));
    await refreshDependencyStatus();

    // 12 minutes of outage, one check every 30 seconds
    for (let check = 0; check < 24; check += 1) {
      await vi.advanceTimersByTimeAsync(CHECK_INTERVAL_MS);
      await refreshDependencyStatus();
    }

    expect(errorSpy).toHaveBeenCalledTimes(1);
    const reminders = failureLogs(warnSpy, '[HEALTH] Dependency still unreachable');
    expect(reminders.map(([, meta]: LogCall) => meta?.outageDurationMs)).toEqual([300_000, 600_000]);
  });

  it('should log an info with the outage duration when the dependency is reachable again', async () => {
    vi.mocked(rabbitMQIsAlive).mockRejectedValue(Error('RabbitMQ seems down'));
    await refreshDependencyStatus();
    await vi.advanceTimersByTimeAsync(CHECK_INTERVAL_MS);
    await refreshDependencyStatus();

    vi.mocked(rabbitMQIsAlive).mockResolvedValue(true);
    await vi.advanceTimersByTimeAsync(CHECK_INTERVAL_MS);
    await refreshDependencyStatus();

    expect(infoSpy).toHaveBeenCalledWith('[HEALTH] Dependency reachable again', { dependency: 'rabbitmq', outageDurationMs: 2 * CHECK_INTERVAL_MS, failedChecks: 2 });
    expect(getPlatformHealthStatus().isHealthy).toBe(true);

    // A new outage is a new event
    vi.mocked(rabbitMQIsAlive).mockRejectedValue(Error('RabbitMQ seems down'));
    await vi.advanceTimersByTimeAsync(CHECK_INTERVAL_MS);
    await refreshDependencyStatus();
    expect(errorSpy).toHaveBeenCalledTimes(2);
  });

  it('should log an error when the dependency is already unreachable at startup', async () => {
    vi.mocked(rabbitMQIsAlive).mockRejectedValue(Error('RabbitMQ seems down'));

    await startPlatformHealthMonitor();
    expect(errorSpy).toHaveBeenCalledTimes(1);
    expect(errorSpy).toHaveBeenCalledWith('[HEALTH] Dependency check failed', { dependency: 'rabbitmq', cause: expect.any(Error) });

    // The next scheduled checks don't log it as an error again
    await vi.advanceTimersByTimeAsync(3 * CHECK_INTERVAL_MS);
    expect(rabbitMQIsAlive).toHaveBeenCalledTimes(4);
    expect(errorSpy).toHaveBeenCalledTimes(1);
  });
});
