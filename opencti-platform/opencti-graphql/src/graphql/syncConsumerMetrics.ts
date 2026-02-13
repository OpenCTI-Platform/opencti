// Sync Consumer Metrics
// Stores consumer metrics received from the remote OpenCTI stream for each Synchronizer.
// When a Synchronizer connects to a remote OpenCTI stream, the remote sends periodic
// consumer_metrics events. This module stores and retrieves those metrics in Redis.

import { logApp } from '../config/conf';
import { getClientBase } from '../database/redis';

const SYNC_METRICS_KEY_PREFIX = '{stream_producer}:';
const SYNC_METRICS_TTL_SECONDS = 120; // 2 minutes, refreshed on each update

export interface SyncConsumerMetricsData {
  connectionId: string;
  connectedAt: string; // ISO string
  lastEventId: string; // consumer's position in the remote stream
  productionRate: number;
  deliveryRate: number;
  processingRate: number;
  resolutionRate: number;
  eventsSentCount: number;
  eventsProcessedCount: number;
  resolutionsSentCount: number;
  timeLag: number;
  estimatedOutOfDepth: number | null;
  lastUpdate: number; // epoch ms
}

/**
 * Store consumer metrics received from the remote stream.
 * Called by the syncManager when a consumer_metrics event is received.
 */
export const storeSyncConsumerMetrics = async (syncId: string, connectionId: string, connectedAt: string, metrics: SyncConsumerMetricsData, lastEventId: string): Promise<void> => {
  try {
    const client = getClientBase();
    const key = `${SYNC_METRICS_KEY_PREFIX}${syncId}`;
    const now_ms = Date.now();
    await client.hset(key, {
      connectionId,
      connectedAt,
      lastEventId,
      productionRate: String(metrics.productionRate ?? 0),
      deliveryRate: String(metrics.deliveryRate ?? 0),
      processingRate: String(metrics.processingRate ?? 0),
      resolutionRate: String(metrics.resolutionRate ?? 0),
      eventsSentCount: String(metrics.eventsSentCount ?? 0),
      eventsProcessedCount: String(metrics.eventsProcessedCount ?? 0),
      resolutionsSentCount: String(metrics.resolutionsSentCount ?? 0),
      timeLag: String(metrics.timeLag ?? 0),
      estimatedOutOfDepth: metrics.estimatedOutOfDepth !== null && metrics.estimatedOutOfDepth !== undefined ? String(metrics.estimatedOutOfDepth) : '',
      lastUpdate: String(now_ms),
    });
    await client.expire(key, SYNC_METRICS_TTL_SECONDS);
  } catch (err) {
    logApp.error('[SYNC] Error storing consumer metrics', { syncId, cause: err });
  }
};

/**
 * Read consumer metrics for a Synchronizer from Redis.
 * Returns null if no metrics are available (sync not running or no data yet).
 */
export const readSyncConsumerMetrics = async (syncId: string): Promise<SyncConsumerMetricsData | null> => {
  try {
    const client = getClientBase();
    const key = `${SYNC_METRICS_KEY_PREFIX}${syncId}`;
    const data = await client.hgetall(key);
    if (!data || Object.keys(data).length === 0) {
      return null;
    }
    return {
      connectionId: data.connectionId,
      connectedAt: data.connectedAt,
      lastEventId: data.lastEventId,
      productionRate: parseFloat(data.productionRate),
      deliveryRate: parseFloat(data.deliveryRate),
      processingRate: parseFloat(data.processingRate),
      resolutionRate: parseFloat(data.resolutionRate),
      eventsSentCount: parseInt(data.eventsSentCount, 10),
      eventsProcessedCount: parseInt(data.eventsProcessedCount, 10),
      resolutionsSentCount: parseInt(data.resolutionsSentCount, 10),
      timeLag: parseFloat(data.timeLag),
      estimatedOutOfDepth: parseFloat(data.estimatedOutOfDepth),
      lastUpdate: parseInt(data.lastUpdate, 10),
    };
  } catch (err) {
    logApp.error('[SYNC] Error reading consumer metrics', { syncId, cause: err });
    return null;
  }
};

/**
 * Clear consumer metrics for a Synchronizer.
 * Called when the sync is stopped or deleted.
 */
export const clearSyncConsumerMetrics = async (syncId: string): Promise<void> => {
  try {
    const client = getClientBase();
    await client.del(`${SYNC_METRICS_KEY_PREFIX}${syncId}`);
  } catch (err) {
    logApp.error('[SYNC] Error clearing consumer metrics', { syncId, cause: err });
  }
};
