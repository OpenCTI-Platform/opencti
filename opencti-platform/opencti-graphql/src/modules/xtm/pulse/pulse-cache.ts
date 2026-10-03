import { getClientBase } from '../../../database/redis';
import { logApp } from '../../../config/conf';
import type { PulseBatch, PulseEventKind } from './pulse-types';

// The {pulse} hash tag keeps every key on one Redis cluster slot, as some commands below touch several keys.
const SALT_PREFIX = '{pulse}:salt:';
const ENTITY_LOOKUP_PREFIX = '{pulse}:entity:';
const RESPONSE_PREFIX = '{pulse}:response:';
const CURSOR_KEY = '{pulse}:cursor';
const OUTBOX_KEY = '{pulse}:outbox';
const STATE_KEY = '{pulse}:state';
const STATS_DAY_PREFIX = '{pulse}:stats:day:';
const STATS_TYPE_KEY = '{pulse}:stats:types';
const ACTIVITY_PREFIX = '{pulse}:activity:';
const TAKEN_SUFFIX = ':taken';
const TRENDING_NOTIFIED_KEY = '{pulse}:trending:notified';

const SALT_TTL_SECONDS = 3 * 24 * 3600;
// The activity of a day can only be contributed with the salt of that day, which XTM Hub keeps for 3 days.
const ACTIVITY_TTL_SECONDS = 3 * 24 * 3600;
const STATS_TTL_SECONDS = 31 * 24 * 3600;
const OUTBOX_MAX_BATCHES = 500;

const parseJson = <T>(raw: string | null, label: string): T | null => {
  if (!raw) {
    return null;
  }
  try {
    return JSON.parse(raw) as T;
  } catch {
    logApp.warn('[THREAT PULSE] Cached value could not be parsed, ignoring', { label });
    return null;
  }
};

// region salts
export const redisGetPulseSalt = async (day: string): Promise<string | null> => getClientBase().get(`${SALT_PREFIX}${day}`);

export const redisSetPulseSalt = async (day: string, salt: string) => {
  await getClientBase().set(`${SALT_PREFIX}${day}`, salt, 'EX', SALT_TTL_SECONDS);
};
// endregion

// region read path caches
export const redisGetPulseEntityLookup = async (entityId: string): Promise<boolean> => {
  return (await getClientBase().exists(`${ENTITY_LOOKUP_PREFIX}${entityId}`)) === 1;
};

export const redisSetPulseEntityLookup = async (entityId: string, ttlSeconds: number) => {
  await getClientBase().set(`${ENTITY_LOOKUP_PREFIX}${entityId}`, '1', 'EX', ttlSeconds);
};

export const redisGetPulseResponse = async <T>(cacheKey: string): Promise<T | null> => {
  return parseJson<T>(await getClientBase().get(`${RESPONSE_PREFIX}${cacheKey}`), cacheKey);
};

export const redisSetPulseResponse = async (cacheKey: string, value: unknown, ttlSeconds: number) => {
  await getClientBase().set(`${RESPONSE_PREFIX}${cacheKey}`, JSON.stringify(value), 'EX', ttlSeconds);
};
// endregion

// region contribution cursor and outbox
export const redisGetPulseCursor = async (): Promise<string | null> => getClientBase().get(CURSOR_KEY);

export const redisSetPulseCursor = async (isoDate: string) => {
  await getClientBase().set(CURSOR_KEY, isoDate);
};

export const redisPushPulseOutbox = async (batches: PulseBatch[]) => {
  if (batches.length === 0) {
    return;
  }
  const client = getClientBase();
  await client.rpush(OUTBOX_KEY, ...batches.map((batch) => JSON.stringify(batch)));
  await client.ltrim(OUTBOX_KEY, -OUTBOX_MAX_BATCHES, -1);
};

export const redisPopPulseOutbox = async (): Promise<PulseBatch[]> => {
  const client = getClientBase();
  const raw = await client.lrange(OUTBOX_KEY, 0, -1);
  if (raw.length > 0) {
    await client.ltrim(OUTBOX_KEY, raw.length, -1);
  }
  return raw.map((entry) => parseJson<PulseBatch>(entry, OUTBOX_KEY)).filter((batch): batch is PulseBatch => batch !== null);
};
// endregion

// region operational state and statistics
export interface PulseOperationalState {
  last_push_at?: string;
  last_refresh_at?: string;
  last_error?: string;
  // 'true' once XTM Hub answered contribution_required to a contributing platform, until its next accepted push.
  contribution_lapsed?: string;
  preview_refresh_at?: string;
  preview_digest_day?: string;
  preview_digest_items?: string;
  preview_matched?: string;
  preview_since?: string;
}

export const redisGetPulseState = async (): Promise<PulseOperationalState> => {
  const raw = await getClientBase().hgetall(STATE_KEY);
  return raw ?? {};
};

export const redisSetPulseState = async (state: PulseOperationalState) => {
  const entries = Object.entries(state).filter(([, value]) => value !== undefined) as Array<[string, string]>;
  const removals = Object.entries(state).filter(([, value]) => value === undefined).map(([key]) => key);
  const client = getClientBase();
  if (entries.length > 0) {
    await client.hset(STATE_KEY, Object.fromEntries(entries));
  }
  if (removals.length > 0) {
    await client.hdel(STATE_KEY, ...removals);
  }
};

export const redisAddPulseContributionStats = async (day: string, records: number, objects: number, recordsByEntityType: Record<string, number>) => {
  const client = getClientBase();
  const dayKey = `${STATS_DAY_PREFIX}${day}`;
  await client.hincrby(dayKey, 'records', records);
  await client.hincrby(dayKey, 'objects', objects);
  await client.expire(dayKey, STATS_TTL_SECONDS);
  const typeEntries = Object.entries(recordsByEntityType);
  for (let index = 0; index < typeEntries.length; index += 1) {
    const [entityType, count] = typeEntries[index];
    await client.hincrby(STATS_TYPE_KEY, entityType, count);
  }
};

export const redisGetPulseContributionStats = async (days: string[]) => {
  const client = getClientBase();
  const perDay = await Promise.all(days.map(async (day) => {
    const values = await client.hgetall(`${STATS_DAY_PREFIX}${day}`);
    return { day, records: Number(values?.records ?? 0), objects: Number(values?.objects ?? 0) };
  }));
  const byType = await client.hgetall(STATS_TYPE_KEY);
  return {
    days: perDay,
    byType: Object.entries(byType ?? {}).map(([entityType, records]) => ({ entity_type: entityType, records: Number(records) })),
  };
};

const activityKeys = (days: string[]) => days.flatMap((day) => [`${ACTIVITY_PREFIX}${day}`, `${ACTIVITY_PREFIX}${day}${TAKEN_SUFFIX}`]);

export const redisClearPulseContributionState = async (days: string[]) => {
  const client = getClientBase();
  await client.del(STATS_TYPE_KEY, OUTBOX_KEY, CURSOR_KEY, TRENDING_NOTIFIED_KEY, ...activityKeys(days), ...days.map((day) => `${STATS_DAY_PREFIX}${day}`));
};
// endregion

// region external activity (hunts and other integrations), kept per UTC day
export interface PulseExternalActivity {
  entityId: string;
  eventKind: PulseEventKind;
  count: number;
}

export const redisAddPulseActivity = async (day: string, entityId: string, eventKind: PulseEventKind, count: number) => {
  const client = getClientBase();
  const key = `${ACTIVITY_PREFIX}${day}`;
  await client.hincrby(key, `${entityId}|${eventKind}`, count);
  await client.expire(key, ACTIVITY_TTL_SECONDS);
};

// Atomically moves the activity of a day into its taken set, adding it to what a run that failed before its
// acknowledgement left there, and returns the whole taken set (RENAME keeps the expiry of the activity key).
const TAKE_ACTIVITY_SCRIPT = `
local activity = KEYS[1]
local taken = KEYS[2]
if redis.call('EXISTS', activity) == 1 then
  if redis.call('EXISTS', taken) == 1 then
    local values = redis.call('HGETALL', activity)
    for index = 1, #values, 2 do
      redis.call('HINCRBY', taken, values[index], values[index + 1])
    end
    redis.call('DEL', activity)
  else
    redis.call('RENAME', activity, taken)
  end
end
return redis.call('HGETALL', taken)
`;

// The activity recorded on *day* and not acknowledged yet. It stays in Redis until redisAckPulseActivity: hunts and
// detections cannot be rebuilt from the database, so a run that fails before pushing them hands them to the next run.
export const redisTakePulseActivity = async (day: string): Promise<PulseExternalActivity[]> => {
  const key = `${ACTIVITY_PREFIX}${day}`;
  const flat = ((await getClientBase().eval(TAKE_ACTIVITY_SCRIPT, 2, key, `${key}${TAKEN_SUFFIX}`)) as string[] | null) ?? [];
  const activity: PulseExternalActivity[] = [];
  for (let index = 0; index + 1 < flat.length; index += 2) {
    const [entityId, eventKind] = flat[index].split('|');
    activity.push({ entityId, eventKind: eventKind as PulseEventKind, count: Number(flat[index + 1]) });
  }
  return activity;
};

// Once the records built from the taken activity are pushed or kept in the outbox.
export const redisAckPulseActivity = async (days: string[]) => {
  if (days.length > 0) {
    await getClientBase().del(...days.map((day) => `${ACTIVITY_PREFIX}${day}${TAKEN_SUFFIX}`));
  }
};

// Opting out: nothing recorded before may leave afterwards.
export const redisDiscardPulseActivity = async (days: string[]) => {
  await getClientBase().del(...activityKeys(days));
};
// endregion

// region trending notifications memory
export const redisFilterNewlyTrending = async (entityIds: string[], memoryDays: number): Promise<string[]> => {
  if (entityIds.length === 0) {
    return [];
  }
  const client = getClientBase();
  const now = Date.now();
  await client.zremrangebyscore(TRENDING_NOTIFIED_KEY, '-inf', now - memoryDays * 24 * 3600 * 1000);
  const scores = await client.zmscore(TRENDING_NOTIFIED_KEY, ...entityIds);
  return entityIds.filter((_, index) => scores[index] === null);
};

export const redisMarkTrendingNotified = async (entityIds: string[]) => {
  if (entityIds.length === 0) {
    return;
  }
  const now = Date.now();
  await getClientBase().zadd(TRENDING_NOTIFIED_KEY, ...entityIds.flatMap((id) => [now, id]));
};
// endregion
