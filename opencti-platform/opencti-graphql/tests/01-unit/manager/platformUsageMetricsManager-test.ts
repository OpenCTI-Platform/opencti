import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { platformStorageUsageMetricsHandler, platformUsageMetricsHandler } from '../../../src/manager/platformUsageMetricsManager';
import { redisGetPlatformStorageUsageMetrics, redisGetPlatformUsageMetrics, redisSetPlatformStorageUsageMetrics, redisSetPlatformUsageMetrics } from '../../../src/database/redis';
import { getEngineUsedSize } from '../../../src/database/engine';
import { getStorageUsedSize } from '../../../src/database/raw-file-storage';
import { getQueueConsumersByType } from '../../../src/database/rabbitmq';
import { registerManager } from '../../../src/manager/managerModule';

vi.mock('../../../src/database/redis', () => ({
  redisGetPlatformUsageMetrics: vi.fn(),
  redisSetPlatformUsageMetrics: vi.fn(),
  redisGetPlatformStorageUsageMetrics: vi.fn(),
  redisSetPlatformStorageUsageMetrics: vi.fn(),
  redisIsAlive: vi.fn(),
}));
vi.mock('../../../src/database/engine', () => ({ getEngineUsedSize: vi.fn(), isEngineAlive: vi.fn() }));
vi.mock('../../../src/database/raw-file-storage', () => ({ getStorageUsedSize: vi.fn(), isStorageAlive: vi.fn() }));
vi.mock('../../../src/database/rabbitmq', () => ({ getQueueConsumersByType: vi.fn(), rabbitMQIsAlive: vi.fn() }));
vi.mock('../../../src/manager/managerModule', () => ({ registerManager: vi.fn() }));

describe('platformUsageMetricsManager: registration', () => {
  // Captured before any clearAllMocks: registration happens once, when the module is imported.
  const registered = vi.mocked(registerManager).mock.calls.map(([definition]) => definition);

  it('should collect on start instead of waiting a full interval after boot', () => {
    expect(registered.map((definition) => definition.id)).toEqual(['PLATFORM_USAGE_METRICS_MANAGER', 'PLATFORM_STORAGE_USAGE_METRICS_MANAGER']);
    registered.forEach((definition) => {
      expect(definition.cronSchedulerHandler?.runOnStart).toBe(true);
    });
    expect(registered[1].cronSchedulerHandler?.interval).toBe(3_600_000);
  });
});

const NOW = Date.UTC(2026, 8, 30, 12, 0, 0);
const minutesAgo = (minutes: number) => NOW - minutes * 60_000;

describe('platformUsageMetricsManager: platformUsageMetricsHandler function', () => {
  const collected = { es_used_size: 10, queue_consumers: { EXTERNAL_IMPORT: 3 } };
  // Interval (300s) plus the probe timeout (15s), with the bucket size kept null for nodes on the previous version.
  const published = { ...collected, s3_used_size: null, collected_at: NOW };
  const TTL = 315;

  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers({ now: NOW });
    vi.mocked(getEngineUsedSize).mockResolvedValue(collected.es_used_size);
    vi.mocked(getQueueConsumersByType).mockResolvedValue(collected.queue_consumers);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('should not recompute when another node already published a value this cycle', async () => {
    vi.mocked(redisGetPlatformUsageMetrics).mockResolvedValue({ ...collected, collected_at: minutesAgo(1) });

    await platformUsageMetricsHandler();

    expect(getEngineUsedSize).not.toHaveBeenCalled();
    expect(getQueueConsumersByType).not.toHaveBeenCalled();
    expect(redisSetPlatformUsageMetrics).not.toHaveBeenCalled();
  });

  it('should collect and publish the shared value when nothing was published yet', async () => {
    vi.mocked(redisGetPlatformUsageMetrics).mockResolvedValue(null);

    await platformUsageMetricsHandler();

    expect(redisSetPlatformUsageMetrics).toHaveBeenCalledWith(published, TTL);
  });

  it('should recompute a value published in the previous cycle, even though it has not expired yet', async () => {
    // The first scheduled tick after the on-start collection lands here: skipping it would let the value expire mid-cycle.
    vi.mocked(redisGetPlatformUsageMetrics).mockResolvedValue({ ...collected, collected_at: minutesAgo(4) });

    await platformUsageMetricsHandler();

    expect(redisSetPlatformUsageMetrics).toHaveBeenCalledWith(published, TTL);
  });

  it('should recompute a value published without collection date by a previous version', async () => {
    vi.mocked(redisGetPlatformUsageMetrics).mockResolvedValue({ ...collected, s3_used_size: 20 });

    await platformUsageMetricsHandler();

    expect(redisSetPlatformUsageMetrics).toHaveBeenCalledWith(published, TTL);
  });

  it('should leave the bucket size to its own collection', async () => {
    vi.mocked(redisGetPlatformUsageMetrics).mockResolvedValue(null);

    await platformUsageMetricsHandler();

    expect(getStorageUsedSize).not.toHaveBeenCalled();
  });

  it('should publish null for a metric that failed to collect, instead of skipping it', async () => {
    vi.mocked(redisGetPlatformUsageMetrics).mockResolvedValue(null);
    vi.mocked(getEngineUsedSize).mockRejectedValue(new Error('ElasticSearch seems down'));

    await platformUsageMetricsHandler();

    expect(redisSetPlatformUsageMetrics).toHaveBeenCalledWith({ ...published, es_used_size: null }, TTL);
  });

  it('should propagate the error and not publish when sharing the collected value fails', async () => {
    vi.mocked(redisGetPlatformUsageMetrics).mockResolvedValue(null);
    vi.mocked(redisSetPlatformUsageMetrics).mockRejectedValue(new Error('Redis seems down'));

    await expect(platformUsageMetricsHandler()).rejects.toThrow('Redis seems down');
  });
});

describe('platformUsageMetricsManager: platformStorageUsageMetricsHandler function', () => {
  // Interval (3600s) plus the bucket scan timeout (120s).
  const TTL = 3720;

  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers({ now: NOW });
    vi.mocked(getStorageUsedSize).mockResolvedValue(20);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('should not rescan the bucket when another node already published its size this cycle', async () => {
    vi.mocked(redisGetPlatformStorageUsageMetrics).mockResolvedValue({ s3_used_size: 20, collected_at: minutesAgo(10) });

    await platformStorageUsageMetricsHandler();

    expect(getStorageUsedSize).not.toHaveBeenCalled();
    expect(redisSetPlatformStorageUsageMetrics).not.toHaveBeenCalled();
  });

  it('should rescan the bucket once its size is from the previous cycle', async () => {
    vi.mocked(redisGetPlatformStorageUsageMetrics).mockResolvedValue({ s3_used_size: 20, collected_at: minutesAgo(58) });

    await platformStorageUsageMetricsHandler();

    expect(redisSetPlatformStorageUsageMetrics).toHaveBeenCalledWith({ s3_used_size: 20, collected_at: NOW }, TTL);
  });

  it('should publish the bucket size with a TTL covering its interval and the next scan', async () => {
    vi.mocked(redisGetPlatformStorageUsageMetrics).mockResolvedValue(null);

    await platformStorageUsageMetricsHandler();

    expect(redisSetPlatformStorageUsageMetrics).toHaveBeenCalledWith({ s3_used_size: 20, collected_at: NOW }, TTL);
    expect(getEngineUsedSize).not.toHaveBeenCalled();
    expect(getQueueConsumersByType).not.toHaveBeenCalled();
  });

  it('should wait past the dependency probe timeout before giving up on the bucket scan', async () => {
    vi.mocked(redisGetPlatformStorageUsageMetrics).mockResolvedValue(null);
    vi.mocked(getStorageUsedSize).mockImplementation(() => new Promise((resolve) => {
      setTimeout(() => resolve(20), 60_000);
    }));

    const handling = platformStorageUsageMetricsHandler();
    await vi.advanceTimersByTimeAsync(60_000);
    await handling;

    expect(redisSetPlatformStorageUsageMetrics).toHaveBeenCalledWith({ s3_used_size: 20, collected_at: NOW + 60_000 }, TTL);
  });

  it('should publish null when the bucket scan exceeds its timeout', async () => {
    vi.mocked(redisGetPlatformStorageUsageMetrics).mockResolvedValue(null);
    vi.mocked(getStorageUsedSize).mockImplementation(() => new Promise(() => {}));

    const handling = platformStorageUsageMetricsHandler();
    await vi.advanceTimersByTimeAsync(120_000);
    await handling;

    expect(redisSetPlatformStorageUsageMetrics).toHaveBeenCalledWith({ s3_used_size: null, collected_at: NOW + 120_000 }, TTL);
  });
});
