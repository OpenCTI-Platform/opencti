import { beforeEach, describe, expect, it, vi } from 'vitest';
import { buildHealthFailures, type DependencyStatus, getPlatformUsageMetrics, type HealthDependency, parseCachedUsageMetrics, syncUsageMetrics } from '../../../src/telemetry/platformHealthMetrics';
import { lockResource, redisGetPlatformUsageMetrics, redisSetPlatformUsageMetrics } from '../../../src/database/redis';
import { getEngineUsedSize } from '../../../src/database/engine';
import { getStorageUsedSize } from '../../../src/database/raw-file-storage';
import { getQueueConsumersByType } from '../../../src/database/rabbitmq';

vi.mock('../../../src/database/redis', () => ({
  lockResource: vi.fn(),
  redisGetPlatformUsageMetrics: vi.fn(),
  redisSetPlatformUsageMetrics: vi.fn(),
  redisIsAlive: vi.fn(),
}));
vi.mock('../../../src/database/engine', () => ({ getEngineUsedSize: vi.fn(), isEngineAlive: vi.fn() }));
vi.mock('../../../src/database/raw-file-storage', () => ({ getStorageUsedSize: vi.fn(), isStorageAlive: vi.fn() }));
vi.mock('../../../src/database/rabbitmq', () => ({ getQueueConsumersByType: vi.fn(), rabbitMQIsAlive: vi.fn() }));

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

describe('platformHealthMetrics: syncUsageMetrics function', () => {
  const collected = { es_used_size: 10, s3_used_size: 20, queue_consumers: { EXTERNAL_IMPORT: 3 } };
  const unlock = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(lockResource).mockResolvedValue({ unlock } as never);
    vi.mocked(getEngineUsedSize).mockResolvedValue(collected.es_used_size);
    vi.mocked(getStorageUsedSize).mockResolvedValue(collected.s3_used_size);
    vi.mocked(getQueueConsumersByType).mockResolvedValue(collected.queue_consumers);
  });

  it('should adopt the value collected by another node instead of recomputing it', async () => {
    vi.mocked(redisGetPlatformUsageMetrics).mockResolvedValue(collected);

    await syncUsageMetrics();

    expect(getPlatformUsageMetrics()).toEqual(collected);
    expect(lockResource).not.toHaveBeenCalled();
    expect(getEngineUsedSize).not.toHaveBeenCalled();
    expect(getStorageUsedSize).not.toHaveBeenCalled();
  });

  it('should collect and share the value when no other node did it', async () => {
    vi.mocked(redisGetPlatformUsageMetrics).mockResolvedValue(null);

    await syncUsageMetrics();

    expect(getPlatformUsageMetrics()).toEqual(collected);
    expect(redisSetPlatformUsageMetrics).toHaveBeenCalledWith(collected, 300);
    expect(unlock).toHaveBeenCalled();
  });

  it('should not collect when another node is already collecting', async () => {
    vi.mocked(redisGetPlatformUsageMetrics).mockResolvedValue(null);
    vi.mocked(lockResource).mockRejectedValue(new Error('Lock already taken'));

    await syncUsageMetrics();

    expect(getEngineUsedSize).not.toHaveBeenCalled();
    expect(getStorageUsedSize).not.toHaveBeenCalled();
    expect(redisSetPlatformUsageMetrics).not.toHaveBeenCalled();
  });

  it('should release the lock when sharing the collected value fails', async () => {
    vi.mocked(redisGetPlatformUsageMetrics).mockResolvedValue(null);
    vi.mocked(redisSetPlatformUsageMetrics).mockRejectedValue(new Error('Redis seems down'));

    await expect(syncUsageMetrics()).rejects.toThrow('Redis seems down');
    expect(unlock).toHaveBeenCalled();
  });
});
