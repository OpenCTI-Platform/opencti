import { beforeEach, describe, expect, it, vi } from 'vitest';
import { adoptSharedUsageMetrics, buildHealthFailures, type DependencyStatus, getPlatformUsageMetrics, type HealthDependency, parseCachedUsageMetrics } from '../../../src/telemetry/platformHealthMetrics';
import { redisGetPlatformUsageMetrics } from '../../../src/database/redis';

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

  it('should keep the previous value when nothing has been published yet', async () => {
    vi.mocked(redisGetPlatformUsageMetrics).mockResolvedValue(shared);
    await adoptSharedUsageMetrics();

    vi.mocked(redisGetPlatformUsageMetrics).mockResolvedValue(null);
    await adoptSharedUsageMetrics();

    expect(getPlatformUsageMetrics()).toEqual(shared);
  });

  it('should keep the previous value when the published payload is invalid', async () => {
    vi.mocked(redisGetPlatformUsageMetrics).mockResolvedValue(shared);
    await adoptSharedUsageMetrics();

    vi.mocked(redisGetPlatformUsageMetrics).mockResolvedValue({ es_used_size: 'nope' });
    await adoptSharedUsageMetrics();

    expect(getPlatformUsageMetrics()).toEqual(shared);
  });
});
