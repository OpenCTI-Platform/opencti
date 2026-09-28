import { type ManagerDefinition, registerManager } from './managerModule';
import conf, { booleanConf, logApp } from '../config/conf';
import { getEngineUsedSize } from '../database/engine';
import { getStorageUsedSize } from '../database/raw-file-storage';
import { getQueueConsumersByType } from '../database/rabbitmq';
import { redisGetPlatformUsageMetrics, redisSetPlatformUsageMetrics } from '../database/redis';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { DEFAULT_USAGE_METRICS_INTERVAL_MS, parseCachedUsageMetrics, type PlatformUsageMetrics, withTimeout } from '../telemetry/platformHealthMetrics';

const PLATFORM_USAGE_METRICS_MANAGER_ENABLED = booleanConf('platform_usage_metrics_manager:enabled', true);
const PLATFORM_USAGE_METRICS_MANAGER_KEY = conf.get('platform_usage_metrics_manager:lock_key') || 'platform_usage_metrics_manager_lock';
// Shares the same config key as the reading side (platformHealthMetrics' adoptSharedUsageMetrics),
// "usage_metrics_interval" is the one interval that drives both how often this manager
// recomputes and how often every node polls the resulting shared value.
const SCHEDULE_TIME = conf.get('app:health_monitoring:usage_metrics_interval') ?? DEFAULT_USAGE_METRICS_INTERVAL_MS;
// Expiring the shared value with the collection interval is what makes exactly one
// node recompute per cycle cluster-wide, the others reading the still valid payload.
const USAGE_METRICS_TTL_SECONDS = Math.max(1, Math.round(SCHEDULE_TIME / 1000));

// A failed collection resets the metric to null so neither Prometheus nor the
// health endpoint reports a stale value as if it were freshly measured.
const collectUsageMetric = async <K extends keyof PlatformUsageMetrics>(
  metrics: PlatformUsageMetrics,
  name: K,
  collect: () => Promise<NonNullable<PlatformUsageMetrics[K]>>,
): Promise<void> => {
  try {
    metrics[name] = await withTimeout(collect(), `Timeout collecting ${name}`);
  } catch (error) {
    metrics[name] = null;
    logApp.warn('[HEALTH] Unable to collect platform usage metric', { metric: name, cause: error });
  }
};

const computeUsageMetrics = async (): Promise<PlatformUsageMetrics> => {
  const context = executionContext('platform_usage_metrics_manager');
  const metrics: PlatformUsageMetrics = { es_used_size: null, s3_used_size: null, queue_consumers: null };
  await Promise.all([
    collectUsageMetric(metrics, 'es_used_size', () => getEngineUsedSize()),
    collectUsageMetric(metrics, 's3_used_size', () => getStorageUsedSize()),
    collectUsageMetric(metrics, 'queue_consumers', () => getQueueConsumersByType(context, SYSTEM_USER)),
  ]);
  return metrics;
};

// The cron manager already guarantees at most one node runs this per tick, but nothing
// synchronizes node timers with each other: re-check the shared cache before collecting,
// so a node that ticks moments after another just published doesn't recompute for nothing.
export const platformUsageMetricsHandler = async (): Promise<void> => {
  const alreadyPublished = parseCachedUsageMetrics(await redisGetPlatformUsageMetrics());
  if (alreadyPublished !== null) {
    return;
  }
  const metrics = await computeUsageMetrics();
  await redisSetPlatformUsageMetrics(metrics, USAGE_METRICS_TTL_SECONDS);
};

const PLATFORM_USAGE_METRICS_MANAGER_DEFINITION: ManagerDefinition = {
  id: 'PLATFORM_USAGE_METRICS_MANAGER',
  label: 'Platform usage metrics manager',
  executionContext: 'platform_usage_metrics_manager',
  cronSchedulerHandler: {
    handler: platformUsageMetricsHandler,
    interval: SCHEDULE_TIME,
    lockKey: PLATFORM_USAGE_METRICS_MANAGER_KEY,
  },
  enabledByConfig: PLATFORM_USAGE_METRICS_MANAGER_ENABLED && SCHEDULE_TIME > 0,
  enabledToStart(): boolean {
    return this.enabledByConfig;
  },
  enabled(): boolean {
    return this.enabledByConfig;
  },
};

registerManager(PLATFORM_USAGE_METRICS_MANAGER_DEFINITION);
