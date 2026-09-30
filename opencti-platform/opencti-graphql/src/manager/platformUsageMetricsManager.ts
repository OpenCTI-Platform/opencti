import { type ManagerDefinition, registerManager } from './managerModule';
import conf, { booleanConf, logApp } from '../config/conf';
import { getEngineUsedSize } from '../database/engine';
import { getStorageUsedSize } from '../database/raw-file-storage';
import { getQueueConsumersByType } from '../database/rabbitmq';
import { redisGetPlatformStorageUsageMetrics, redisGetPlatformUsageMetrics, redisSetPlatformStorageUsageMetrics, redisSetPlatformUsageMetrics } from '../database/redis';
import { executionContext, SYSTEM_USER } from '../utils/access';
import {
  CHECK_TIMEOUT_MS,
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
// The shared value outlives its interval by the collection timeout, so it's still readable while the next
// collection runs; a value missing a whole cycle (collection stopped cluster-wide) expires rather than going stale.
const toTtlSeconds = (intervalMs: number, timeoutMs: number) => Math.max(1, Math.ceil((intervalMs + timeoutMs) / 1000));

// Since the value outlives its interval, freshness, not presence, decides whether a tick recomputes:
// a value published less than half an interval ago comes from another node's tick in this same cycle.
// Payloads without a collection date (published by a previous version) are always recomputed.
const isPublishedThisCycle = (cached: unknown, intervalMs: number) => {
  const collectedAt = (cached as { collected_at?: unknown } | null)?.collected_at;
  return typeof collectedAt === 'number' && Date.now() - collectedAt < intervalMs / 2;
};

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
  publish: (payload: T & { collected_at: number }, ttlSeconds: number) => Promise<void>,
  intervalMs: number,
  timeoutMs: number,
) => async (): Promise<void> => {
  const cached = await read();
  if (parse(cached) !== null && isPublishedThisCycle(cached, intervalMs)) {
    return;
  }
  const metrics = await compute();
  await publish({ ...metrics, collected_at: Date.now() }, toTtlSeconds(intervalMs, timeoutMs));
};

export const platformUsageMetricsHandler = buildSharedMetricsHandler(
  redisGetPlatformUsageMetrics,
  parseCachedUsageMetrics,
  computeUsageMetrics,
  // Nodes running the version before the bucket size got its own key reject a payload without
  // s3_used_size, and their manager then rescans the bucket: keep it, null, for mixed-version clusters.
  (payload, ttlSeconds) => redisSetPlatformUsageMetrics({ ...payload, s3_used_size: null }, ttlSeconds),
  SCHEDULE_TIME,
  CHECK_TIMEOUT_MS,
);

export const platformStorageUsageMetricsHandler = buildSharedMetricsHandler(
  redisGetPlatformStorageUsageMetrics,
  parseCachedStorageUsageMetrics,
  computeStorageUsageMetrics,
  redisSetPlatformStorageUsageMetrics,
  STORAGE_SCHEDULE_TIME,
  STORAGE_COLLECT_TIMEOUT,
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
