import { type ManagerDefinition, registerManager } from './managerModule';
import conf, { booleanConf, logApp } from '../config/conf';
import { getEngineUsedSize } from '../database/engine';
import { getStorageUsedSize } from '../database/raw-file-storage';
import { getQueueConsumersByType } from '../database/rabbitmq';
import { redisGetPlatformStorageUsageMetrics, redisGetPlatformUsageMetrics, redisSetPlatformStorageUsageMetrics, redisSetPlatformUsageMetrics } from '../database/redis';
import { executionContext, SYSTEM_USER } from '../utils/access';
import {
  DEFAULT_STORAGE_USAGE_METRICS_INTERVAL_MS,
  DEFAULT_STORAGE_USAGE_METRICS_TIMEOUT_MS,
  DEFAULT_USAGE_METRICS_INTERVAL_MS,
  parseCachedStorageUsageMetrics,
  parseCachedUsageMetrics,
  type PlatformUsageMetrics,
  type SharedStorageUsageMetrics,
  type SharedUsageMetrics,
  withTimeout,
} from '../telemetry/platformHealthMetrics';

const PLATFORM_USAGE_METRICS_MANAGER_ENABLED = booleanConf('platform_usage_metrics_manager:enabled', true);
const PLATFORM_USAGE_METRICS_MANAGER_KEY = conf.get('platform_usage_metrics_manager:lock_key') || 'platform_usage_metrics_manager_lock';
const PLATFORM_STORAGE_USAGE_METRICS_MANAGER_KEY = conf.get('platform_usage_metrics_manager:storage_lock_key') || 'platform_storage_usage_metrics_manager_lock';
// Shares the same config key as the reading side (platformHealthMetrics' adoptSharedUsageMetrics),
// "usage_metrics_interval" is the one interval that drives both how often this manager
// recomputes and how often every node polls the resulting shared value.
const SCHEDULE_TIME = conf.get('app:health_monitoring:usage_metrics_interval') ?? DEFAULT_USAGE_METRICS_INTERVAL_MS;
// The bucket size is a full bucket scan whose duration grows with the number of stored files,
// so it runs on its own, longer, schedule and with a timeout sized for large buckets.
const STORAGE_SCHEDULE_TIME = conf.get('app:health_monitoring:storage_usage_metrics_interval') ?? DEFAULT_STORAGE_USAGE_METRICS_INTERVAL_MS;
const STORAGE_COLLECT_TIMEOUT = conf.get('app:health_monitoring:storage_usage_metrics_timeout') ?? DEFAULT_STORAGE_USAGE_METRICS_TIMEOUT_MS;
// Expiring the shared value with the collection interval is what makes exactly one
// node recompute per cycle cluster-wide, the others reading the still valid payload.
const toTtlSeconds = (intervalMs: number) => Math.max(1, Math.round(intervalMs / 1000));

// A failed collection resets the metric to null so neither Prometheus nor the
// health endpoint reports a stale value as if it were freshly measured.
const collectUsageMetric = async <T extends object, K extends keyof T & keyof PlatformUsageMetrics>(
  metrics: T,
  name: K,
  collect: () => Promise<NonNullable<T[K]>>,
  timeoutMs?: number,
): Promise<void> => {
  try {
    metrics[name] = await withTimeout(collect(), `Timeout collecting ${name}`, timeoutMs);
  } catch (error) {
    metrics[name] = null as T[K];
    logApp.warn('[HEALTH] Unable to collect platform usage metric', { metric: name, cause: error });
  }
};

const computeUsageMetrics = async (): Promise<SharedUsageMetrics> => {
  const context = executionContext('platform_usage_metrics_manager');
  const metrics: SharedUsageMetrics = { es_used_size: null, queue_consumers: null };
  await Promise.all([
    collectUsageMetric(metrics, 'es_used_size', () => getEngineUsedSize()),
    collectUsageMetric(metrics, 'queue_consumers', () => getQueueConsumersByType(context, SYSTEM_USER)),
  ]);
  return metrics;
};

const computeStorageUsageMetrics = async (): Promise<SharedStorageUsageMetrics> => {
  const metrics: SharedStorageUsageMetrics = { s3_used_size: null };
  await collectUsageMetric(metrics, 's3_used_size', () => getStorageUsedSize(), STORAGE_COLLECT_TIMEOUT);
  return metrics;
};

// The cron manager already guarantees at most one node runs this per tick, but nothing
// synchronizes node timers with each other: re-check the shared cache before collecting,
// so a node that ticks moments after another just published doesn't recompute for nothing.
const buildSharedMetricsHandler = <T extends object>(
  read: () => Promise<unknown>,
  parse: (cached: unknown) => T | null,
  compute: () => Promise<T>,
  publish: (metrics: T, ttlSeconds: number) => Promise<void>,
  intervalMs: number,
) => async (): Promise<void> => {
  const alreadyPublished = parse(await read());
  if (alreadyPublished !== null) {
    return;
  }
  const metrics = await compute();
  await publish(metrics, toTtlSeconds(intervalMs));
};

export const platformUsageMetricsHandler = buildSharedMetricsHandler(
  redisGetPlatformUsageMetrics,
  parseCachedUsageMetrics,
  computeUsageMetrics,
  redisSetPlatformUsageMetrics,
  SCHEDULE_TIME,
);

export const platformStorageUsageMetricsHandler = buildSharedMetricsHandler(
  redisGetPlatformStorageUsageMetrics,
  parseCachedStorageUsageMetrics,
  computeStorageUsageMetrics,
  redisSetPlatformStorageUsageMetrics,
  STORAGE_SCHEDULE_TIME,
);

// Run on start: the first scheduled tick only fires one interval after boot, which would leave
// the metrics empty for up to an hour after a deploy. Concurrent starts across nodes are still
// deduplicated by the lock and the shared cache check.
const buildManagerDefinition = (id: string, label: string, handler: () => Promise<void>, interval: number, lockKey: string): ManagerDefinition => ({
  id,
  label,
  executionContext: 'platform_usage_metrics_manager',
  cronSchedulerHandler: { handler, interval, lockKey, runOnStart: true },
  enabledByConfig: PLATFORM_USAGE_METRICS_MANAGER_ENABLED && interval > 0,
  enabledToStart(): boolean {
    return this.enabledByConfig;
  },
  enabled(): boolean {
    return this.enabledByConfig;
  },
});

registerManager(buildManagerDefinition(
  'PLATFORM_USAGE_METRICS_MANAGER',
  'Platform usage metrics manager',
  platformUsageMetricsHandler,
  SCHEDULE_TIME,
  PLATFORM_USAGE_METRICS_MANAGER_KEY,
));
registerManager(buildManagerDefinition(
  'PLATFORM_STORAGE_USAGE_METRICS_MANAGER',
  'Platform storage usage metrics manager',
  platformStorageUsageMetricsHandler,
  STORAGE_SCHEDULE_TIME,
  PLATFORM_STORAGE_USAGE_METRICS_MANAGER_KEY,
));
