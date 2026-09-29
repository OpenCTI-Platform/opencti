import { beforeEach, describe, expect, it, vi } from 'vitest';
import { platformStorageUsageMetricsHandler, platformUsageMetricsHandler } from '../../../src/manager/platformUsageMetricsManager';
import { redisGetPlatformStorageUsageMetrics, redisGetPlatformUsageMetrics, redisSetPlatformStorageUsageMetrics, redisSetPlatformUsageMetrics } from '../../../src/database/redis';
import { getEngineUsedSize } from '../../../src/database/engine';
import { getStorageUsedSize } from '../../../src/database/raw-file-storage';
import { getQueueConsumersByType } from '../../../src/database/rabbitmq';

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

describe('platformUsageMetricsManager: platformUsageMetricsHandler function', () => {
  const collected = { es_used_size: 10, queue_consumers: { EXTERNAL_IMPORT: 3 } };

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(getEngineUsedSize).mockResolvedValue(collected.es_used_size);
    vi.mocked(getQueueConsumersByType).mockResolvedValue(collected.queue_consumers);
  });

  it('should not recompute when another node already published a value this cycle', async () => {
    vi.mocked(redisGetPlatformUsageMetrics).mockResolvedValue(collected);

    await platformUsageMetricsHandler();

    expect(getEngineUsedSize).not.toHaveBeenCalled();
    expect(getQueueConsumersByType).not.toHaveBeenCalled();
    expect(redisSetPlatformUsageMetrics).not.toHaveBeenCalled();
  });

  it('should collect and publish the shared value when nothing was published yet', async () => {
    vi.mocked(redisGetPlatformUsageMetrics).mockResolvedValue(null);

    await platformUsageMetricsHandler();

    expect(redisSetPlatformUsageMetrics).toHaveBeenCalledWith(collected, 300);
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

    expect(redisSetPlatformUsageMetrics).toHaveBeenCalledWith({ ...collected, es_used_size: null }, 300);
  });

  it('should propagate the error and not publish when sharing the collected value fails', async () => {
    vi.mocked(redisGetPlatformUsageMetrics).mockResolvedValue(null);
    vi.mocked(redisSetPlatformUsageMetrics).mockRejectedValue(new Error('Redis seems down'));

    await expect(platformUsageMetricsHandler()).rejects.toThrow('Redis seems down');
  });
});

describe('platformUsageMetricsManager: platformStorageUsageMetricsHandler function', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useRealTimers();
    vi.mocked(getStorageUsedSize).mockResolvedValue(20);
  });

  it('should not rescan the bucket when another node already published its size this cycle', async () => {
    vi.mocked(redisGetPlatformStorageUsageMetrics).mockResolvedValue({ s3_used_size: 20 });

    await platformStorageUsageMetricsHandler();

    expect(getStorageUsedSize).not.toHaveBeenCalled();
    expect(redisSetPlatformStorageUsageMetrics).not.toHaveBeenCalled();
  });

  it('should publish the bucket size with a TTL matching its own interval', async () => {
    vi.mocked(redisGetPlatformStorageUsageMetrics).mockResolvedValue(null);

    await platformStorageUsageMetricsHandler();

    expect(redisSetPlatformStorageUsageMetrics).toHaveBeenCalledWith({ s3_used_size: 20 }, 3600);
    expect(getEngineUsedSize).not.toHaveBeenCalled();
    expect(getQueueConsumersByType).not.toHaveBeenCalled();
  });

  it('should wait past the dependency probe timeout before giving up on the bucket scan', async () => {
    vi.useFakeTimers();
    vi.mocked(redisGetPlatformStorageUsageMetrics).mockResolvedValue(null);
    vi.mocked(getStorageUsedSize).mockImplementation(() => new Promise((resolve) => {
      setTimeout(() => resolve(20), 60_000);
    }));

    const handling = platformStorageUsageMetricsHandler();
    await vi.advanceTimersByTimeAsync(60_000);
    await handling;

    expect(redisSetPlatformStorageUsageMetrics).toHaveBeenCalledWith({ s3_used_size: 20 }, 3600);
    vi.useRealTimers();
  });

  it('should publish null when the bucket scan exceeds its timeout', async () => {
    vi.useFakeTimers();
    vi.mocked(redisGetPlatformStorageUsageMetrics).mockResolvedValue(null);
    vi.mocked(getStorageUsedSize).mockImplementation(() => new Promise(() => {}));

    const handling = platformStorageUsageMetricsHandler();
    await vi.advanceTimersByTimeAsync(120_000);
    await handling;

    expect(redisSetPlatformStorageUsageMetrics).toHaveBeenCalledWith({ s3_used_size: null }, 3600);
    vi.useRealTimers();
  });
});
