import { ValueType } from '@opentelemetry/api';
import conf, { logApp } from '../config/conf';
import { meterManager } from '../config/tracing';
import { getEngineUsedSize, isEngineAlive } from '../database/engine';
import { getStorageUsedSize, isStorageAlive } from '../database/raw-file-storage';
import { getQueueConsumersByType, rabbitMQIsAlive } from '../database/rabbitmq';
import { lockResource, redisGetPlatformUsageMetrics, redisIsAlive, redisSetPlatformUsageMetrics } from '../database/redis';
import { executionContext, SYSTEM_USER } from '../utils/access';

export const HEALTH_DEPENDENCIES = ['elasticsearch', 'storage', 'rabbitmq', 'redis'] as const;
export type HealthDependency = typeof HEALTH_DEPENDENCIES[number];

export interface DependencyStatus {
  isAlive: boolean;
  error: string | null;
  checkedAt: number | null;
}

export interface PlatformUsageMetrics {
  es_used_size: number | null;
  s3_used_size: number | null;
  queue_consumers: Record<string, number> | null;
}

export interface PlatformHealthStatus {
  initialized: boolean;
  isHealthy: boolean;
  failures: string[];
  dependencies: Record<HealthDependency, boolean>;
}

const CHECK_TIMEOUT_MS = 15_000;
const DEFAULT_DEPENDENCY_CHECK_INTERVAL_MS = 30_000;
const DEFAULT_USAGE_METRICS_INTERVAL_MS = 300_000;
const USAGE_METRICS_LOCK = 'platform-usage-metrics';

const buildInitialStatuses = (): Record<HealthDependency, DependencyStatus> => {
  return HEALTH_DEPENDENCIES.reduce((statuses, dependency) => {
    return { ...statuses, [dependency]: { isAlive: false, error: null, checkedAt: null } };
  }, {} as Record<HealthDependency, DependencyStatus>);
};

const buildInitialUsageMetrics = (): PlatformUsageMetrics => ({ es_used_size: null, s3_used_size: null, queue_consumers: null });

let dependencyStatuses = buildInitialStatuses();
let usageMetrics: PlatformUsageMetrics = buildInitialUsageMetrics();
let dependencyCheckInterval: NodeJS.Timeout | null = null;
let usageMetricsInterval: NodeJS.Timeout | null = null;
let usageMetricsTtlSeconds = DEFAULT_USAGE_METRICS_INTERVAL_MS / 1000;
let gaugesRegistered = false;

const dependencyProbes: Record<HealthDependency, () => Promise<unknown>> = {
  elasticsearch: isEngineAlive,
  storage: isStorageAlive,
  rabbitmq: rabbitMQIsAlive,
  redis: redisIsAlive,
};

// Bound a probe so one unresponsive dependency cannot stall the whole refresh cycle.
const withTimeout = async <T>(promise: Promise<T>, message: string): Promise<T> => {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(Error(message)), CHECK_TIMEOUT_MS);
  });
  try {
    return await Promise.race([promise, timeout]);
  } finally {
    clearTimeout(timer);
  }
};

// Only dependencies that have actually been probed can be declared failing:
// a not-yet-checked dependency is reported through the initialized flag instead.
export const buildHealthFailures = (statuses: Record<HealthDependency, DependencyStatus>): string[] => {
  return HEALTH_DEPENDENCIES
    .filter((dependency) => statuses[dependency].checkedAt !== null && !statuses[dependency].isAlive)
    .map((dependency) => `${dependency}: ${statuses[dependency].error ?? 'unavailable'}`);
};

export const refreshDependencyStatus = async (): Promise<void> => {
  await Promise.all(HEALTH_DEPENDENCIES.map(async (dependency) => {
    try {
      await withTimeout(dependencyProbes[dependency](), `Timeout checking ${dependency} health`);
      dependencyStatuses[dependency] = { isAlive: true, error: null, checkedAt: Date.now() };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      dependencyStatuses[dependency] = { isAlive: false, error: message, checkedAt: Date.now() };
      logApp.error('[HEALTH] Dependency check failed', { dependency, cause: error });
    }
  }));
};

// A failed collection resets the metric to null so neither Prometheus nor the
// health endpoint reports a stale value as if it were freshly measured.
const collectUsageMetric = async <K extends keyof PlatformUsageMetrics>(
  name: K,
  collect: () => Promise<NonNullable<PlatformUsageMetrics[K]>>,
): Promise<void> => {
  try {
    usageMetrics[name] = await withTimeout(collect(), `Timeout collecting ${name}`);
  } catch (error) {
    usageMetrics[name] = null;
    logApp.warn('[HEALTH] Unable to collect platform usage metric', { metric: name, cause: error });
  }
};

const refreshUsageMetrics = async (): Promise<void> => {
  const context = executionContext('health_monitoring');
  await Promise.all([
    collectUsageMetric('es_used_size', () => getEngineUsedSize()),
    collectUsageMetric('s3_used_size', () => getStorageUsedSize()),
    collectUsageMetric('queue_consumers', () => getQueueConsumersByType(context, SYSTEM_USER)),
  ]);
};

const isNullableNumber = (value: unknown): value is number | null => value === null || typeof value === 'number';

// Redis holds whatever the node that won the last collection wrote, so the payload is
// validated before being adopted rather than trusted to still match the current shape.
export const parseCachedUsageMetrics = (cached: unknown): PlatformUsageMetrics | null => {
  if (cached === null || typeof cached !== 'object') {
    return null;
  }
  const { es_used_size, s3_used_size, queue_consumers } = cached as Record<keyof PlatformUsageMetrics, unknown>;
  if (!isNullableNumber(es_used_size) || !isNullableNumber(s3_used_size)) {
    return null;
  }
  if (queue_consumers !== null && (typeof queue_consumers !== 'object' || !Object.values(queue_consumers as object).every((count) => typeof count === 'number'))) {
    return null;
  }
  return { es_used_size, s3_used_size, queue_consumers: queue_consumers as Record<string, number> | null };
};

const readSharedUsageMetrics = async (): Promise<PlatformUsageMetrics | null> => {
  return parseCachedUsageMetrics(await redisGetPlatformUsageMetrics());
};

// Collection is expensive (full bucket scan, engine stats) and its result is cluster wide,
// so nodes share a single Redis value: the first node to take the lock computes it for
// everyone else, and the others simply adopt the cached payload on their next cycle.
export const syncUsageMetrics = async (): Promise<void> => {
  const cached = await readSharedUsageMetrics();
  if (cached !== null) {
    usageMetrics = cached;
    return;
  }
  let lock;
  try {
    lock = await lockResource([USAGE_METRICS_LOCK], { retryCount: 0, automaticExtension: false });
  } catch {
    // Another node is already collecting: keep the values from the previous cycle.
    return;
  }
  try {
    // Re-read under the lock: a node may have published between our read and our acquisition.
    const published = await readSharedUsageMetrics();
    if (published !== null) {
      usageMetrics = published;
      return;
    }
    await refreshUsageMetrics();
    await redisSetPlatformUsageMetrics(usageMetrics, usageMetricsTtlSeconds);
  } finally {
    await lock.unlock();
  }
};

const registerHealthGauges = () => {
  if (gaugesRegistered) {
    return;
  }
  const meter = meterManager.meterProvider.getMeter('opencti-platform-health');
  const dependencyUpGauge = meter.createObservableGauge('opencti_dependency_up', {
    valueType: ValueType.INT,
    description: 'Connectivity state of a platform dependency (1 up, 0 down)',
  });
  dependencyUpGauge.addCallback((result) => {
    HEALTH_DEPENDENCIES.forEach((dependency) => {
      if (dependencyStatuses[dependency].checkedAt !== null) {
        result.observe(dependencyStatuses[dependency].isAlive ? 1 : 0, { dependency });
      }
    });
  });
  const esUsedSizeGauge = meter.createObservableGauge('opencti_elasticsearch_used_size_bytes', {
    valueType: ValueType.INT,
    description: 'Total Elasticsearch/OpenSearch primary store size, replicas excluded',
  });
  esUsedSizeGauge.addCallback((result) => {
    if (usageMetrics.es_used_size !== null) {
      result.observe(usageMetrics.es_used_size);
    }
  });
  const storageUsedSizeGauge = meter.createObservableGauge('opencti_storage_used_size_bytes', {
    valueType: ValueType.INT,
    description: 'Total S3/MinIO bucket object size',
  });
  storageUsedSizeGauge.addCallback((result) => {
    if (usageMetrics.s3_used_size !== null) {
      result.observe(usageMetrics.s3_used_size);
    }
  });
  const queueConsumersGauge = meter.createObservableGauge('opencti_queue_consumers', {
    valueType: ValueType.INT,
    description: 'Number of active consumers on the push queues, per connector type',
  });
  queueConsumersGauge.addCallback((result) => {
    Object.entries(usageMetrics.queue_consumers ?? {}).forEach(([connectorType, consumers]) => {
      result.observe(consumers, { connector_type: connectorType });
    });
  });
  gaugesRegistered = true;
};

export const getPlatformHealthStatus = (): PlatformHealthStatus => {
  const initialized = HEALTH_DEPENDENCIES.every((dependency) => dependencyStatuses[dependency].checkedAt !== null);
  const failures = buildHealthFailures(dependencyStatuses);
  const dependencies = HEALTH_DEPENDENCIES.reduce((states, dependency) => {
    return { ...states, [dependency]: dependencyStatuses[dependency].isAlive };
  }, {} as Record<HealthDependency, boolean>);
  return { initialized, isHealthy: initialized && failures.length === 0, failures, dependencies };
};

export const getPlatformUsageMetrics = (): PlatformUsageMetrics => {
  const { queue_consumers } = usageMetrics;
  return { ...usageMetrics, queue_consumers: queue_consumers === null ? null : { ...queue_consumers } };
};

export const startPlatformHealthMonitor = async (): Promise<void> => {
  if (dependencyCheckInterval) {
    return; // Already running
  }
  registerHealthGauges();
  const dependencyCheckIntervalMs = conf.get('app:health_monitoring:dependency_check_interval') ?? DEFAULT_DEPENDENCY_CHECK_INTERVAL_MS;
  const usageMetricsIntervalMs = conf.get('app:health_monitoring:usage_metrics_interval') ?? DEFAULT_USAGE_METRICS_INTERVAL_MS;
  // Expiring the shared value with the collection interval is what makes exactly one
  // node recompute per cycle, the others reading the still valid payload.
  usageMetricsTtlSeconds = Math.max(1, Math.round(usageMetricsIntervalMs / 1000));
  // Awaited so the health endpoint exposes a meaningful state as soon as the API accepts traffic.
  await refreshDependencyStatus();
  dependencyCheckInterval = setInterval(() => {
    refreshDependencyStatus().catch((error) => {
      logApp.error('[HEALTH] Dependency status refresh failed', { cause: error });
    });
  }, dependencyCheckIntervalMs);
  if (usageMetricsIntervalMs > 0) {
    // Usage metrics are expensive (full bucket scan), so they are never awaited on the startup path.
    usageMetricsInterval = setInterval(() => {
      syncUsageMetrics().catch((error) => {
        logApp.error('[HEALTH] Usage metrics refresh failed', { cause: error });
      });
    }, usageMetricsIntervalMs);
    syncUsageMetrics().catch((error) => {
      logApp.error('[HEALTH] Usage metrics refresh failed', { cause: error });
    });
  }
  logApp.info('[HEALTH] Platform health monitoring started', { dependencyCheckIntervalMs, usageMetricsIntervalMs });
};

export const stopPlatformHealthMonitor = (): void => {
  if (dependencyCheckInterval) {
    clearInterval(dependencyCheckInterval);
    dependencyCheckInterval = null;
  }
  if (usageMetricsInterval) {
    clearInterval(usageMetricsInterval);
    usageMetricsInterval = null;
  }
  dependencyStatuses = buildInitialStatuses();
  usageMetrics = buildInitialUsageMetrics();
  logApp.info('[HEALTH] Platform health monitoring stopped');
};
