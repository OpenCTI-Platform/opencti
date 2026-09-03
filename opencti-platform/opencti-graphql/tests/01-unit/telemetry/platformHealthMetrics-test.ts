import { describe, expect, it } from 'vitest';
import { buildHealthFailures, type DependencyStatus, type HealthDependency } from '../../../src/telemetry/platformHealthMetrics';

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
