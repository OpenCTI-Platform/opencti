import { ValueType } from '@opentelemetry/api';
import conf, { logApp } from '../config/conf';
import { meterManager } from '../config/tracing';
import { getEngineUsedSize, isEngineAlive } from '../database/engine';
import { getStorageUsedSize, isStorageAlive } from '../database/raw-file-storage';
import { getIngestionUnits, rabbitMQIsAlive } from '../database/rabbitmq';
import { redisIsAlive } from '../database/redis';
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
  ingestion_units: number | null;
}

export interface PlatformHealthStatus {
  initialized: boolean;
  isHealthy: boolean;
  failures: string[];
}

const CHECK_TIMEOUT_MS = 15_000;
const DEFAULT_CONNECTIVITY_INTERVAL_MS = 30_000;
const DEFAULT_USAGE_METRICS_INTERVAL_MS = 300_000;

const buildInitialStatuses = (): Record<HealthDependency, DependencyStatus> => {
  return HEALTH_DEPENDENCIES.reduce((statuses, dependency) => {
    return { ...statuses, [dependency]: { isAlive: false, error: null, checkedAt: null } };
  }, {} as Record<HealthDependency, DependencyStatus>);
};

let dependencyStatuses = buildInitialStatuses();
let usageMetrics: PlatformUsageMetrics = { es_used_size: null, s3_used_size: null, ingestion_units: null };
let connectivityInterval: NodeJS.Timeout | null = null;
let usageMetricsInterval: NodeJS.Timeout | null = null;
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

export const refreshConnectivityMetrics = async (): Promise<void> => {
  await Promise.all(HEALTH_DEPENDENCIES.map(async (dependency) => {
    try {
      await withTimeout(dependencyProbes[dependency](), `Timeout checking ${dependency} health`);
      dependencyStatuses[dependency] = { isAlive: true, error: null, checkedAt: Date.now() };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      dependencyStatuses[dependency] = { isAlive: false, error: message, checkedAt: Date.now() };
      logApp.error('[HEALTH] Dependency connectivity check failed', { dependency, cause: error });
    }
  }));
};

// A failed collection resets the metric to null so neither Prometheus nor the
// health endpoint reports a stale value as if it were freshly measured.
const collectUsageMetric = async (name: keyof PlatformUsageMetrics, collect: () => Promise<number>): Promise<void> => {
  try {
    usageMetrics[name] = await withTimeout(collect(), `Timeout collecting ${name}`);
  } catch (error) {
    usageMetrics[name] = null;
    logApp.warn('[HEALTH] Unable to collect platform usage metric', { metric: name, cause: error });
  }
};

export const refreshUsageMetrics = async (): Promise<void> => {
  const context = executionContext('health_monitoring');
  await Promise.all([
    collectUsageMetric('es_used_size', () => getEngineUsedSize()),
    collectUsageMetric('s3_used_size', () => getStorageUsedSize()),
    collectUsageMetric('ingestion_units', () => getIngestionUnits(context, SYSTEM_USER)),
  ]);
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
  const ingestionUnitsGauge = meter.createObservableGauge('opencti_ingestion_units', {
    valueType: ValueType.INT,
    description: 'Number of active consumers on ingestion connector queues',
  });
  ingestionUnitsGauge.addCallback((result) => {
    if (usageMetrics.ingestion_units !== null) {
      result.observe(usageMetrics.ingestion_units);
    }
  });
  gaugesRegistered = true;
};

export const getPlatformHealthStatus = (): PlatformHealthStatus => {
  const initialized = HEALTH_DEPENDENCIES.every((dependency) => dependencyStatuses[dependency].checkedAt !== null);
  const failures = buildHealthFailures(dependencyStatuses);
  return { initialized, isHealthy: initialized && failures.length === 0, failures };
};

export const getPlatformUsageMetrics = (): PlatformUsageMetrics => {
  return { ...usageMetrics };
};

export const startPlatformHealthMonitor = async (): Promise<void> => {
  if (connectivityInterval) {
    return; // Already running
  }
  registerHealthGauges();
  const connectivityIntervalMs = conf.get('app:health_monitoring:connectivity_interval') ?? DEFAULT_CONNECTIVITY_INTERVAL_MS;
  const usageMetricsIntervalMs = conf.get('app:health_monitoring:usage_metrics_interval') ?? DEFAULT_USAGE_METRICS_INTERVAL_MS;
  // Awaited so the health endpoint exposes a meaningful state as soon as the API accepts traffic.
  await refreshConnectivityMetrics();
  connectivityInterval = setInterval(() => {
    refreshConnectivityMetrics().catch((error) => {
      logApp.error('[HEALTH] Connectivity metrics refresh failed', { cause: error });
    });
  }, connectivityIntervalMs);
  if (usageMetricsIntervalMs > 0) {
    // Usage metrics are expensive (full bucket scan), so they are never awaited on the startup path.
    usageMetricsInterval = setInterval(() => {
      refreshUsageMetrics().catch((error) => {
        logApp.error('[HEALTH] Usage metrics refresh failed', { cause: error });
      });
    }, usageMetricsIntervalMs);
    refreshUsageMetrics().catch((error) => {
      logApp.error('[HEALTH] Usage metrics refresh failed', { cause: error });
    });
  }
  logApp.info('[HEALTH] Platform health monitoring started', { connectivityIntervalMs, usageMetricsIntervalMs });
};

export const stopPlatformHealthMonitor = (): void => {
  if (connectivityInterval) {
    clearInterval(connectivityInterval);
    connectivityInterval = null;
  }
  if (usageMetricsInterval) {
    clearInterval(usageMetricsInterval);
    usageMetricsInterval = null;
  }
  dependencyStatuses = buildInitialStatuses();
  usageMetrics = { es_used_size: null, s3_used_size: null, ingestion_units: null };
  logApp.info('[HEALTH] Platform health monitoring stopped');
};
