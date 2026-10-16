import { logApp } from '../../config/conf';
import { RUNTIME_DATA, RUNTIME_DATA_TYPES, type RuntimeData, type RuntimeDataType, type RuntimeDataValue } from './ingestionHealth-registry';
import { createStorage, type RuntimeDataStorage } from './ingestionHealthRuntimeData-storage';

export type { RuntimeData, RuntimeDataType };

// Runtime data feeding the runtime health checks, written by several sources and read by the ingestion health manager.
// RUNTIME_DATA, in the registry, is the only place declaring a type: its value format and where it is stored.
// This module only stores and returns what was reported, it does not judge it: what is stale or missing
// is up to the ingestion health manager.
const STORAGES = Object.fromEntries(
  RUNTIME_DATA_TYPES.map((type) => [type, createStorage(RUNTIME_DATA[type].storage)]),
) as Record<RuntimeDataType, RuntimeDataStorage>;

// Throws if the value does not match the format of its type
export const setRuntimeData = async <T extends RuntimeDataType>(ingestionId: string, type: T, value: RuntimeDataValue<T>) => {
  await STORAGES[type].set(ingestionId, RUNTIME_DATA[type].schema.parse(value));
};

export const removeRuntimeData = async (ingestionId: string, type: RuntimeDataType) => {
  await STORAGES[type].remove(ingestionId);
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
  const valuesByType = await Promise.all(types.map((type) => STORAGES[type].getMany(ingestionIds)));
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
