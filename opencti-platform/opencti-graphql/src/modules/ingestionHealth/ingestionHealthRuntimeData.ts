import { z } from 'zod';
import { logApp } from '../../config/conf';
import { type RuntimeDataStorage, redisSortedSet } from './ingestionHealthRuntimeData-storage';

// Runtime data feeding the ingestion health checks, written by several sources and read by the ingestion health manager.
// The registry is the only place declaring a type: its value format and where it is stored.
// Changing the storage of a type is changing its `storage` line, see ingestionHealthRuntimeData-storage.
// This module only stores and returns what was reported, it does not judge it: what is stale or missing
// is up to the ingestion health manager.
const RUNTIME_DATA = {
  // Last time a connector pinged or registered (ISO date).
  // Kept in the sorted set of the connector liveness: it has no expiration, the age of the value is judged by the manager.
  heartbeat: {
    schema: z.iso.datetime(),
    storage: redisSortedSet<string>({
      key: 'connector_heartbeats',
      toScore: (iso) => new Date(iso).getTime(),
      fromScore: (epochMs) => new Date(epochMs).toISOString(),
    }),
  },
} as const satisfies Record<string, { schema: z.ZodType; storage: RuntimeDataStorage<any> }>;

export type RuntimeDataType = keyof typeof RUNTIME_DATA;
export type RuntimeDataValue<T extends RuntimeDataType> = z.infer<(typeof RUNTIME_DATA)[T]['schema']>;
export type RuntimeData = { [T in RuntimeDataType]?: RuntimeDataValue<T> };

const RUNTIME_DATA_TYPES = Object.keys(RUNTIME_DATA) as RuntimeDataType[];

// Throws if the value does not match the format of its type
export const setRuntimeData = async <T extends RuntimeDataType>(ingestionId: string, type: T, value: RuntimeDataValue<T>) => {
  const { schema, storage } = RUNTIME_DATA[type];
  await storage.set(ingestionId, schema.parse(value));
};

export const removeRuntimeData = async (ingestionId: string, type: RuntimeDataType) => {
  await RUNTIME_DATA[type].storage.remove(ingestionId);
};

// Only valid data is returned. A value that cannot be read in the expected format
// (written by another platform version for instance) is ignored, as if it was absent.
const parseRuntimeData = (ingestionId: string, type: RuntimeDataType, raw: unknown): unknown => {
  const result = RUNTIME_DATA[type].schema.safeParse(raw);
  if (result.success) {
    return result.data;
  }
  logApp.warn('[OPENCTI-MODULE] Ignoring invalid ingestion runtime data', { ingestionId, type, issues: result.error.issues });
  return undefined;
};

/**
 * Reads the runtime data of a batch of ingestions.
 *
 * One storage call per type, whatever the number of ingestions (for instance a single ZMSCORE for the heartbeat),
 * instead of one call per ingestion. The ingestion health manager reads a whole source at once: the ids are the
 * connectors, feeds or syncs, a few hundreds at most, so the payload and the time held in memory stay small.
 * If it ever grows to thousands, the caller can split its ids in chunks, this function does not need to change.
 *
 * What is returned is what the sources reported, as stored: no freshness is applied. A heartbeat recorded
 * a week ago is returned as is, and the caller judges whether it is stale (see isHeartbeatAlive).
 *
 * - Absent data is omitted: an ingestion that reported nothing has no entry in the map.
 * - A value that is not in the expected format (written by another platform version for instance)
 *   is ignored with a warning, as if it was absent.
 * - A storage failure is not hidden: it rejects, so that an unreachable storage is never read as "no data".
 *
 * @param ingestionIds the ingestions to read, an empty list does not call any storage
 * @param types the types to read, all by default
 * @returns the data per ingestion id
 */
export const getRuntimeDataMany = async (ingestionIds: string[], types: RuntimeDataType[] = RUNTIME_DATA_TYPES): Promise<Map<string, RuntimeData>> => {
  const result = new Map<string, RuntimeData>();
  if (ingestionIds.length === 0) {
    return result;
  }
  const valuesByType = await Promise.all(types.map((type) => RUNTIME_DATA[type].storage.getMany(ingestionIds)));
  types.forEach((type, index) => {
    valuesByType[index].forEach((raw, ingestionId) => {
      const data = parseRuntimeData(ingestionId, type, raw);
      if (data !== undefined) {
        const runtimeData: Record<string, unknown> = result.get(ingestionId) ?? {};
        runtimeData[type] = data;
        result.set(ingestionId, runtimeData as RuntimeData);
      }
    });
  });
  return result;
};

// Reads one ingestion
export const getRuntimeData = async (ingestionId: string, types?: RuntimeDataType[]): Promise<RuntimeData> => {
  return (await getRuntimeDataMany([ingestionId], types)).get(ingestionId) ?? {};
};
