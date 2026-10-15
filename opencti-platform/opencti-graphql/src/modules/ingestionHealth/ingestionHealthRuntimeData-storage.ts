import { getClientBase } from '../../database/redis';
import { logApp } from '../../config/conf';

// Where a runtime data type is stored. A storage only moves raw values: it knows nothing about
// the format of the value (validated by the registry) nor about its freshness (judged by the manager).
export interface RuntimeDataStorage<V> {
  set: (ingestionId: string, value: V) => Promise<void>;
  // Absent ingestions are omitted from the result. Batch so that one call reads every ingestion of a cycle.
  getMany: (ingestionIds: string[]) => Promise<Map<string, unknown>>;
  remove: (ingestionId: string) => Promise<void>;
}

// region redis string: one key per ingestion, the value is stored as JSON
// ttlSec is only a clean-up of the key, not a freshness: a value is never judged by its presence.
export const redisString = <V>({ key, ttlSec }: { key: (ingestionId: string) => string; ttlSec?: number }): RuntimeDataStorage<V> => ({
  set: async (ingestionId, value) => {
    const json = JSON.stringify(value);
    if (ttlSec) {
      await getClientBase().set(key(ingestionId), json, 'EX', ttlSec);
    } else {
      await getClientBase().set(key(ingestionId), json);
    }
  },
  getMany: async (ingestionIds) => {
    const result = new Map<string, unknown>();
    // A pipeline, not an MGET: keys of different ingestions are in different slots in cluster mode
    const pipeline = getClientBase().pipeline();
    ingestionIds.forEach((ingestionId) => pipeline.get(key(ingestionId)));
    const replies = await pipeline.exec() ?? [];
    replies.forEach(([err, raw], index) => {
      if (err) {
        throw err;
      }
      if (raw === null || raw === undefined) {
        return;
      }
      try {
        result.set(ingestionIds[index], JSON.parse(raw as string));
      } catch (cause) {
        logApp.warn('[OPENCTI-MODULE] Ignoring unreadable ingestion runtime data', { cause, ingestionId: ingestionIds[index] });
      }
    });
    return result;
  },
  remove: async (ingestionId) => {
    await getClientBase().del(key(ingestionId));
  },
});
// endregion

// region redis sorted set: one member per ingestion (member: ingestion id), the value is encoded in the score
// A single key, so that it can be listed in one call, cluster included.
export const redisSortedSet = <V>({ key, toScore, fromScore }: {
  key: string;
  toScore: (value: V) => number;
  fromScore: (score: number) => V;
}): RuntimeDataStorage<V> => ({
  set: async (ingestionId, value) => {
    await getClientBase().zadd(key, toScore(value), ingestionId);
  },
  getMany: async (ingestionIds) => {
    const result = new Map<string, unknown>();
    const scores = await getClientBase().zmscore(key, ...ingestionIds);
    scores.forEach((score, index) => {
      if (score !== null && score !== undefined) {
        result.set(ingestionIds[index], fromScore(Number(score)));
      }
    });
    return result;
  },
  remove: async (ingestionId) => {
    await getClientBase().zrem(key, ingestionId);
  },
});
// endregion
