// Stream Consumer Registry
// Hybrid in-memory + Redis tracking of connected SSE consumers for StreamCollections.
// Hot-path event tracking stays in-memory; consumer registration and periodic metric
// snapshots are stored in Redis so all OpenCTI instances see all consumers.

import { logApp } from '../config/conf';
import { getClientBase } from '../database/redis';

// -- Constants --

const SLIDING_WINDOW_SIZE = 60; // Keep 60 seconds of rate data
const SLIDING_WINDOW_BUCKET_MS = 1000; // 1-second buckets
const FLUSH_INTERVAL_MS = 5000; // Flush metrics to Redis every 5 seconds
const CONSUMER_TTL_SECONDS = 60; // Redis key TTL; refreshed on each flush
const STALE_CUTOFF_MS = CONSUMER_TTL_SECONDS * 1000;

// Redis key prefixes
const CONSUMER_KEY_PREFIX = 'stream_consumer:';
const COLLECTION_SET_PREFIX = 'stream_consumers:';

// -- Types --

interface RateBucket {
  timestamp: number;
  count: number;
}

// Local in-memory tracking (only for consumers connected to THIS instance)
interface LocalConsumerTracking {
  connectionId: string;
  collectionId: string;
  lastEventId: string;
  eventsSentCount: number;
  eventsProcessedCount: number;
  resolutionsSentCount: number; // dependency/missing resolution events sent
  recentDeliveries: RateBucket[];
  recentProcessed: RateBucket[];
  recentResolutions: RateBucket[];
}

// Data shape returned when reading consumers from Redis
export interface RedisConsumerData {
  connectionId: string;
  collectionId: string;
  userId: string;
  userEmail: string;
  connectedAt: string; // ISO string
  lastEventId: string;
  eventsSentCount: number;
  eventsProcessedCount: number;
  deliveryRate: number;
  processingRate: number;
  resolutionRate: number; // dependency/missing resolution events per second
  lastUpdate: number; // epoch ms
}

// -- In-memory state (local to this instance) --

const localConsumers = new Map<string, LocalConsumerTracking>();
let flushInterval: ReturnType<typeof setInterval> | null = null;

// -- Sliding window helpers --

const pruneOldBuckets = (buckets: RateBucket[], now_ms: number): RateBucket[] => {
  const cutoff = now_ms - (SLIDING_WINDOW_SIZE * 1000);
  return buckets.filter((b) => b.timestamp >= cutoff);
};

const addToBuckets = (buckets: RateBucket[], count: number, now_ms: number): RateBucket[] => {
  const pruned = pruneOldBuckets(buckets, now_ms);
  const bucketTime = Math.floor(now_ms / SLIDING_WINDOW_BUCKET_MS) * SLIDING_WINDOW_BUCKET_MS;
  const lastBucket = pruned.length > 0 ? pruned[pruned.length - 1] : null;
  if (lastBucket && lastBucket.timestamp === bucketTime) {
    lastBucket.count += count;
  } else {
    pruned.push({ timestamp: bucketTime, count });
  }
  return pruned;
};

const computeRate = (buckets: RateBucket[]): number => {
  if (buckets.length < 2) {
    if (buckets.length === 1) {
      return buckets[0].count;
    }
    return 0;
  }
  const now_ms = Date.now();
  const pruned = pruneOldBuckets(buckets, now_ms);
  if (pruned.length === 0) return 0;
  const totalCount = pruned.reduce((sum, b) => sum + b.count, 0);
  const timeSpanMs = now_ms - pruned[0].timestamp;
  if (timeSpanMs <= 0) return totalCount;
  return totalCount / (timeSpanMs / 1000);
};

// -- Redis helpers --

const consumerRedisKey = (connectionId: string) => `${CONSUMER_KEY_PREFIX}${connectionId}`;
const collectionSetKey = (collectionId: string) => `${COLLECTION_SET_PREFIX}${collectionId}`;

// -- Public API --

/**
 * Register a new consumer. Writes to Redis + creates local tracking entry.
 * Called when an SSE connection is established.
 */
export const registerConsumer = async (
  connectionId: string,
  collectionId: string,
  userId: string,
  userEmail: string,
): Promise<void> => {
  const now_ms = Date.now();
  const connectedAt = new Date(now_ms).toISOString();

  // Write consumer hash to Redis
  const client = getClientBase();
  const key = consumerRedisKey(connectionId);
  const pipeline = client.pipeline();
  pipeline.hset(key, {
    connectionId,
    collectionId,
    userId,
    userEmail,
    connectedAt,
    lastEventId: '',
    eventsSentCount: '0',
    eventsProcessedCount: '0',
    resolutionsSentCount: '0',
    deliveryRate: '0',
    processingRate: '0',
    resolutionRate: '0',
    lastUpdate: String(now_ms),
  });
  pipeline.expire(key, CONSUMER_TTL_SECONDS);
  // Add to collection sorted set (score = current timestamp)
  pipeline.zadd(collectionSetKey(collectionId), now_ms, connectionId);
  await pipeline.exec();

  // Create local in-memory tracking
  localConsumers.set(connectionId, {
    connectionId,
    collectionId,
    lastEventId: '',
    eventsSentCount: 0,
    eventsProcessedCount: 0,
    resolutionsSentCount: 0,
    recentDeliveries: [],
    recentProcessed: [],
    recentResolutions: [],
  });
};

/**
 * Unregister a consumer. Removes from Redis + local tracking.
 * Called when an SSE connection is closed.
 */
export const unregisterConsumer = async (connectionId: string): Promise<void> => {
  const local = localConsumers.get(connectionId);
  const collectionId = local?.collectionId;

  // Remove from local map
  localConsumers.delete(connectionId);

  // Remove from Redis
  try {
    const client = getClientBase();
    const pipeline = client.pipeline();
    pipeline.del(consumerRedisKey(connectionId));
    if (collectionId) {
      pipeline.zrem(collectionSetKey(collectionId), connectionId);
    }
    await pipeline.exec();
  } catch (err) {
    logApp.error('[STREAM] Error unregistering consumer from Redis', { connectionId, cause: err });
  }
};

/**
 * Track events delivered to a consumer (after filtering).
 * Synchronous, in-memory only -- hot path.
 */
export const trackEventDelivered = (connectionId: string, count: number = 1): void => {
  const consumer = localConsumers.get(connectionId);
  if (consumer) {
    const now_ms = Date.now();
    consumer.eventsSentCount += count;
    consumer.recentDeliveries = addToBuckets(consumer.recentDeliveries, count, now_ms);
  }
};

/**
 * Track events processed from Redis stream (before filtering).
 * Synchronous, in-memory only -- hot path.
 */
export const trackEventsProcessed = (connectionId: string, count: number, lastEventId: string): void => {
  const consumer = localConsumers.get(connectionId);
  if (consumer) {
    const now_ms = Date.now();
    consumer.eventsProcessedCount += count;
    consumer.lastEventId = lastEventId;
    consumer.recentProcessed = addToBuckets(consumer.recentProcessed, count, now_ms);
  }
};

/**
 * Track missing resolution / dependency events sent to a consumer.
 * Synchronous, in-memory only -- hot path.
 */
export const trackMissingResolution = (connectionId: string, count: number = 1): void => {
  const consumer = localConsumers.get(connectionId);
  if (consumer) {
    const now_ms = Date.now();
    consumer.resolutionsSentCount += count;
    consumer.recentResolutions = addToBuckets(consumer.recentResolutions, count, now_ms);
  }
};

/**
 * Flush local metrics to Redis for all consumers on this instance.
 * Called periodically by the flush interval.
 */
const flushMetricsToRedis = async (): Promise<void> => {
  if (localConsumers.size === 0) return;

  try {
    const client = getClientBase();
    const pipeline = client.pipeline();
    const now_ms = Date.now();

    for (const consumer of localConsumers.values()) {
      const deliveryRate = computeRate(consumer.recentDeliveries);
      const processingRate = computeRate(consumer.recentProcessed);
      const resolutionRate = computeRate(consumer.recentResolutions);

      const key = consumerRedisKey(consumer.connectionId);
      pipeline.hset(key, {
        lastEventId: consumer.lastEventId,
        eventsSentCount: String(consumer.eventsSentCount),
        eventsProcessedCount: String(consumer.eventsProcessedCount),
        resolutionsSentCount: String(consumer.resolutionsSentCount),
        deliveryRate: String(Math.round(deliveryRate * 100) / 100),
        processingRate: String(Math.round(processingRate * 100) / 100),
        resolutionRate: String(Math.round(resolutionRate * 100) / 100),
        lastUpdate: String(now_ms),
      });
      pipeline.expire(key, CONSUMER_TTL_SECONDS);

      // Refresh sorted set score
      pipeline.zadd(collectionSetKey(consumer.collectionId), now_ms, consumer.connectionId);
    }

    await pipeline.exec();
  } catch (err) {
    logApp.error('[STREAM] Error flushing consumer metrics to Redis', { cause: err });
  }
};

/**
 * Start the periodic metrics flush to Redis.
 * Should be called once at SSE middleware initialization.
 */
export const startConsumerMetricsFlush = (): void => {
  if (flushInterval) return; // Already running
  flushInterval = setInterval(() => {
    flushMetricsToRedis().catch((err) => {
      logApp.error('[STREAM] Metrics flush error', { cause: err });
    });
  }, FLUSH_INTERVAL_MS);
  logApp.info('[STREAM] Consumer metrics flush started');
};

/**
 * Stop the periodic metrics flush. For clean shutdown.
 */
export const stopConsumerMetricsFlush = (): void => {
  if (flushInterval) {
    clearInterval(flushInterval);
    flushInterval = null;
    logApp.info('[STREAM] Consumer metrics flush stopped');
  }
};

/**
 * Get all consumers for a given collection from Redis.
 * Reads from the sorted set + individual hashes.
 * Works across all instances.
 */
export const getConsumersForCollection = async (collectionId: string): Promise<RedisConsumerData[]> => {
  const client = getClientBase();
  const setKey = collectionSetKey(collectionId);
  const now_ms = Date.now();
  const staleCutoff = now_ms - STALE_CUTOFF_MS;

  // Get connectionIds from the sorted set that are recent enough
  const connectionIds = await client.zrangebyscore(setKey, staleCutoff, '+inf');
  if (connectionIds.length === 0) return [];

  // Clean up stale entries (older than cutoff)
  await client.zremrangebyscore(setKey, '-inf', staleCutoff - 1).catch(() => {});

  // Fetch each consumer hash
  const results: RedisConsumerData[] = [];
  const pipeline = client.pipeline();
  for (const connId of connectionIds) {
    pipeline.hgetall(consumerRedisKey(connId));
  }
  const pipelineResults = await pipeline.exec();

  if (pipelineResults) {
    for (let i = 0; i < pipelineResults.length; i += 1) {
      const [err, data] = pipelineResults[i];
      if (!err && data && typeof data === 'object' && Object.keys(data as object).length > 0) {
        const hash = data as Record<string, string>;
        results.push({
          connectionId: hash.connectionId || connectionIds[i],
          collectionId: hash.collectionId || collectionId,
          userId: hash.userId || '',
          userEmail: hash.userEmail || '',
          connectedAt: hash.connectedAt || '',
          lastEventId: hash.lastEventId || '',
          eventsSentCount: parseInt(hash.eventsSentCount || '0', 10),
          eventsProcessedCount: parseInt(hash.eventsProcessedCount || '0', 10),
          deliveryRate: parseFloat(hash.deliveryRate || '0'),
          processingRate: parseFloat(hash.processingRate || '0'),
          resolutionRate: parseFloat(hash.resolutionRate || '0'),
          lastUpdate: parseInt(hash.lastUpdate || '0', 10),
        });
      }
    }
  }

  return results;
};
