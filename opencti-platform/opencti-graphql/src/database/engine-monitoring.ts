// region Engine health monitoring CRON
import { Client as ElkClient } from '@elastic/elasticsearch';
import { isFeatureEnabled, logApp } from '../config/conf';
import { engine, oebp } from './engine';

const HEALTH_MONITOR_INTERVAL_MS = 60_000; // 1 minute
let healthMonitorInterval: NodeJS.Timeout | null = null;

const elGetClusterHealth = async () => {
  try {
    // 1. Cluster health
    const healthResult = engine instanceof ElkClient
      ? await engine.cluster.health()
      : await engine.cluster.health();
    const health = oebp(healthResult);
    logApp.info('[SEARCH] Cluster health', {
      status: health.status,
      numberOfNodes: health.number_of_nodes,
      numberOfDataNodes: health.number_of_data_nodes,
      activePrimaryShards: health.active_primary_shards,
      activeShards: health.active_shards,
      relocatingShards: health.relocating_shards,
      initializingShards: health.initializing_shards,
      unassignedShards: health.unassigned_shards,
      activeShardsPercentAsNumber: health.active_shards_percent_as_number,
    });

    // 2. Node stats (JVM heap, CPU, OS memory)
    const nodesStatsResult = engine instanceof ElkClient
      ? await engine.nodes.stats({ metric: ['jvm', 'os', 'process'] as any })
      : await engine.nodes.stats({ metric: 'jvm,os,process' } as any);
    const nodesStats = oebp(nodesStatsResult);
    const nodeEntries = Object.entries(nodesStats.nodes ?? {}) as [string, any][];
    for (const [nodeId, node] of nodeEntries) {
      const jvmHeapUsedBytes = node.jvm?.mem?.heap_used_in_bytes ?? 0;
      const jvmHeapMaxBytes = node.jvm?.mem?.heap_max_in_bytes ?? 1;
      const jvmHeapUsedPercent = Math.round((jvmHeapUsedBytes / jvmHeapMaxBytes) * 100);
      logApp.info('[SEARCH] Node stats', {
        nodeId,
        nodeName: node.name,
        cpuPercent: node.os?.cpu?.percent,
        osMemTotalBytes: node.os?.mem?.total_in_bytes,
        osMemFreeBytes: node.os?.mem?.free_in_bytes,
        osMemUsedPercent: node.os?.mem?.used_percent,
        jvmHeapUsedBytes,
        jvmHeapMaxBytes,
        jvmHeapUsedPercent,
        jvmGcYoungCollectionCount: node.jvm?.gc?.collectors?.young?.collection_count,
        jvmGcYoungCollectionTimeMs: node.jvm?.gc?.collectors?.young?.collection_time_in_millis,
        jvmGcOldCollectionCount: node.jvm?.gc?.collectors?.old?.collection_count,
        jvmGcOldCollectionTimeMs: node.jvm?.gc?.collectors?.old?.collection_time_in_millis,
        openFileDescriptors: node.process?.open_file_descriptors,
      });
    }

    // 3. Thread pool stats (queue sizes, rejections)
    const threadPoolResult = engine instanceof ElkClient
      ? await engine.cat.threadPool({ format: 'json', h: 'node_name,name,active,queue,rejected,completed' as any })
      : await engine.cat.threadPool({ format: 'json', h: ['node_name', 'name', 'active', 'queue', 'rejected', 'completed'] } as any);
    const threadPools = oebp(threadPoolResult) as any[];
    const monitoredPools = ['search', 'write', 'bulk', 'get', 'analyze', 'management'];
    const relevantPools = (threadPools ?? []).filter(
      (tp: any) => monitoredPools.includes(tp.name) && (Number(tp.active) > 0 || Number(tp.queue) > 0 || Number(tp.rejected) > 0),
    );
    if (relevantPools.length > 0) {
      for (const tp of relevantPools) {
        logApp.info('[SEARCH] Thread pool stats', {
          nodeName: tp.node_name,
          pool: tp.name,
          active: Number(tp.active),
          queue: Number(tp.queue),
          rejected: Number(tp.rejected),
          completed: Number(tp.completed),
        });
      }
    } else {
      logApp.info('[SEARCH] Thread pool stats: all monitored pools idle (no active, queued, or rejected tasks)');
    }
  } catch (e) {
    logApp.error('[SEARCH] Error fetching cluster health', { cause: e });
  }
};

export const startEngineHealthMonitor = () => {
  const engineMonitorActivated = isFeatureEnabled('ENGINE_MONITORING');
  if (!engineMonitorActivated || healthMonitorInterval) {
    return; // Already running
  }
  logApp.info('[SEARCH] Starting engine health monitoring CRON (every 1 minute)');
  healthMonitorInterval = setInterval(elGetClusterHealth, HEALTH_MONITOR_INTERVAL_MS);
};

export const stopEngineHealthMonitor = () => {
  if (healthMonitorInterval) {
    clearInterval(healthMonitorInterval);
    healthMonitorInterval = null;
    logApp.info('[SEARCH] Engine health monitoring CRON stopped');
  }
};
// endregion
