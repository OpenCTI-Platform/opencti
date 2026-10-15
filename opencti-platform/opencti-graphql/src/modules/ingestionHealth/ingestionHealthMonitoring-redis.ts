import { z } from 'zod';
import { getClientBase } from '../../database/redis';
import { logApp } from '../../config/conf';

// Runtime data feeding the ingestion health checks, written by several sources and read by the ingestion health manager.
// One Redis key per ingestion and per type: ingestion_health:{<ingestionId>}:<type>
// The hash tag keeps the keys of one ingestion in one cluster slot, so the manager reads them with a single MGET per ingestion.
// The registry is the only place declaring a type: its value format and how long it stays valid (Redis TTL, no timestamp stored).
// A missing key means never reported or expired.
const RUNTIME_DATA = {
  // Last time a connector pinged or registered (ISO date). Same 5 minutes window as the connector liveness.
  heartbeat: { schema: z.iso.datetime(), ttl: 5 * 60 },
} as const satisfies Record<string, { schema: z.ZodType; ttl: number }>;

export type RuntimeDataType = keyof typeof RUNTIME_DATA;
export type RuntimeDataValue<T extends RuntimeDataType> = z.infer<(typeof RUNTIME_DATA)[T]['schema']>;
export type RuntimeData = { [T in RuntimeDataType]?: RuntimeDataValue<T> };

const RUNTIME_DATA_TYPES = Object.keys(RUNTIME_DATA) as RuntimeDataType[];
const runtimeDataKey = (ingestionId: string, type: RuntimeDataType) => `ingestion_health:{${ingestionId}}:${type}`;

// Throws if the value does not match the format of its type
export const redisSetRuntimeData = async <T extends RuntimeDataType>(ingestionId: string, type: T, value: RuntimeDataValue<T>) => {
  const { schema, ttl } = RUNTIME_DATA[type];
  const data = schema.parse(value);
  await getClientBase().set(runtimeDataKey(ingestionId, type), JSON.stringify(data), 'EX', ttl);
};

// Only valid data is returned. A value that cannot be read in the expected format
// (written by another platform version for instance) is ignored, as if it was absent.
const parseRuntimeData = (ingestionId: string, type: RuntimeDataType, raw: string): unknown => {
  try {
    const result = RUNTIME_DATA[type].schema.safeParse(JSON.parse(raw));
    if (result.success) {
      return result.data;
    }
    logApp.warn('[OPENCTI-MODULE] Ignoring invalid ingestion runtime data', { ingestionId, type, issues: result.error.issues });
  } catch (err) {
    logApp.warn('[OPENCTI-MODULE] Ignoring unreadable ingestion runtime data', { cause: err, ingestionId, type });
  }
  return undefined;
};

// Reads every type of one ingestion, absent data is omitted
export const redisGetRuntimeData = async (ingestionId: string): Promise<RuntimeData> => {
  const values = await getClientBase().mget(RUNTIME_DATA_TYPES.map((type) => runtimeDataKey(ingestionId, type)));
  const runtimeData: Record<string, unknown> = {};
  RUNTIME_DATA_TYPES.forEach((type, index) => {
    const raw = values[index];
    const data = raw === null ? undefined : parseRuntimeData(ingestionId, type, raw);
    if (data !== undefined) {
      runtimeData[type] = data;
    }
  });
  return runtimeData as RuntimeData;
};
