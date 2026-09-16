import { beforeEach, describe, expect, it, vi } from 'vitest';
import { platformUsageMetricsHandler } from '../../../src/manager/platformUsageMetricsManager';
import { redisGetPlatformUsageMetrics, redisSetPlatformUsageMetrics } from '../../../src/database/redis';
import { getEngineUsedSize } from '../../../src/database/engine';
import { getStorageUsedSize } from '../../../src/database/raw-file-storage';
import { getQueueConsumersByType } from '../../../src/database/rabbitmq';

vi.mock('../../../src/database/redis', () => ({
  redisGetPlatformUsageMetrics: vi.fn(),
  redisSetPlatformUsageMetrics: vi.fn(),
  redisIsAlive: vi.fn(),
}));
vi.mock('../../../src/database/engine', () => ({ getEngineUsedSize: vi.fn(), isEngineAlive: vi.fn() }));
vi.mock('../../../src/database/raw-file-storage', () => ({ getStorageUsedSize: vi.fn(), isStorageAlive: vi.fn() }));
vi.mock('../../../src/database/rabbitmq', () => ({ getQueueConsumersByType: vi.fn(), rabbitMQIsAlive: vi.fn() }));

describe('platformUsageMetricsManager: platformUsageMetricsHandler function', () => {
  const collected = { es_used_size: 10, s3_used_size: 20, queue_consumers: { EXTERNAL_IMPORT: 3 } };

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(getEngineUsedSize).mockResolvedValue(collected.es_used_size);
    vi.mocked(getStorageUsedSize).mockResolvedValue(collected.s3_used_size);
    vi.mocked(getQueueConsumersByType).mockResolvedValue(collected.queue_consumers);
  });

  it('should not recompute when another node already published a value this cycle', async () => {
    vi.mocked(redisGetPlatformUsageMetrics).mockResolvedValue(collected);

    await platformUsageMetricsHandler();

    expect(getEngineUsedSize).not.toHaveBeenCalled();
    expect(getStorageUsedSize).not.toHaveBeenCalled();
    expect(getQueueConsumersByType).not.toHaveBeenCalled();
    expect(redisSetPlatformUsageMetrics).not.toHaveBeenCalled();
  });

  it('should collect and publish the shared value when nothing was published yet', async () => {
    vi.mocked(redisGetPlatformUsageMetrics).mockResolvedValue(null);

    await platformUsageMetricsHandler();

    expect(redisSetPlatformUsageMetrics).toHaveBeenCalledWith(collected, 300);
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
