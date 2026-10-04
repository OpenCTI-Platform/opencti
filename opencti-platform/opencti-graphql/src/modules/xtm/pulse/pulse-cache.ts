import { getClientBase } from '../../../database/redis';
import { logApp } from '../../../config/conf';
import type { PulseEventKind, PulseOutboxItem } from './pulse-types';

// The {pulse} hash tag keeps every key on one Redis cluster slot, as some commands below touch several keys.
const SALT_PREFIX = '{pulse}:salt:';
const ENTITY_LOOKUP_PREFIX = '{pulse}:entity:';
const RESPONSE_PREFIX = '{pulse}:response:';
const CURSOR_KEY = '{pulse}:cursor';
const OUTBOX_KEY = '{pulse}:outbox';
const OUTBOX_INFLIGHT_KEY = '{pulse}:outbox:inflight';
const CONFIG_GENERATION_KEY = '{pulse}:config:generation';
const STATE_KEY = '{pulse}:state';
const STATS_DAY_PREFIX = '{pulse}:stats:day:';
// The per-type counters of the first builds, one hash for all days: only deleted now.
const STATS_TYPE_KEY = '{pulse}:stats:types';
const STATS_TYPE_FIELD_PREFIX = 'type:';
const POLICY_GENERATION_KEY = '{pulse}:policy:generation';
const ACTIVITY_PREFIX = '{pulse}:activity:';
const TAKEN_SUFFIX = ':taken';
const TRENDING_NOTIFIED_KEY = '{pulse}:trending:notified';

const SALT_TTL_SECONDS = 3 * 24 * 3600;
// The activity of a day can only be contributed with the salt of that day, which XTM Hub keeps for 3 days.
const ACTIVITY_TTL_SECONDS = 3 * 24 * 3600;
const STATS_TTL_SECONDS = 31 * 24 * 3600;

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

// Moves with every change of the Threat Pulse configuration, once the new one is stored: a contribution cycle started
// under another configuration neither records nor sends what it collected.
export const redisGetPulseConfigGeneration = async (): Promise<string> => (await getClientBase().get(CONFIG_GENERATION_KEY)) ?? '0';

export const redisBumpPulseConfigGeneration = async () => {
  await getClientBase().incr(CONFIG_GENERATION_KEY);
};

// Moves before the privacy policy narrows (a scope removed, a marking excluded, the contribution stopped): every batch
// carries the policy generation it was built under, and a batch of an earlier one is never sent.
export const redisGetPulsePolicyGeneration = async (): Promise<string> => (await getClientBase().get(POLICY_GENERATION_KEY)) ?? '0';

export const redisBumpPulsePolicyGeneration = async () => {
  await getClientBase().incr(POLICY_GENERATION_KEY);
};

// KEYS: generation, outbox, cursor, then the activity keys to acknowledge. ARGV: the generation of the cycle, the
// cursor, then the batches.
const COMMIT_WINDOW_SCRIPT = `
if (redis.call('GET', KEYS[1]) or '0') ~= ARGV[1] then
  return 0
end
for index = 3, #ARGV do
  redis.call('RPUSH', KEYS[2], ARGV[index])
end
redis.call('SET', KEYS[3], ARGV[2])
for index = 4, #KEYS do
  redis.call('DEL', KEYS[index])
end
return 1
`;

// The batches of a contribution window, the cursor after it and the acknowledgement of the activity taken from Redis,
// in one script (every key shares the {pulse} slot): all of them are written, or none when the configuration changed
// since the cycle started. The outbox is never trimmed: a run whose pending batches XTM Hub did not answer collects no
// new window, and a batch whose salt day XTM Hub no longer accepts is dropped when claimed, so it holds at most one
// window beyond the accepted days.
export const redisCommitPulseWindow = async (items: PulseOutboxItem[], cursor: string, ackDays: string[], generation: string): Promise<boolean> => {
  const ackKeys = ackDays.map((day) => `${ACTIVITY_PREFIX}${day}${TAKEN_SUFFIX}`);
  const committed = await getClientBase().eval(
    COMMIT_WINDOW_SCRIPT,
    3 + ackKeys.length,
    CONFIG_GENERATION_KEY,
    OUTBOX_KEY,
    CURSOR_KEY,
    ...ackKeys,
    generation,
    cursor,
    ...items.map((item) => JSON.stringify(item)),
  );
  return committed === 1;
};

// Atomically moves the pending batches into the in-flight list, after what a run that stopped before settling its
// batches left there, and returns the whole in-flight list.
const CLAIM_OUTBOX_SCRIPT = `
local outbox = KEYS[1]
local inflight = KEYS[2]
local pending = redis.call('LRANGE', outbox, 0, -1)
for index = 1, #pending do
  redis.call('RPUSH', inflight, pending[index])
end
redis.call('DEL', outbox)
return redis.call('LRANGE', inflight, 0, -1)
`;

// Removes a settled batch and, when XTM Hub accepted it, adds its statistics: both happen once, in one script, however
// many times a run settles the same entry.
// The records per entity type are kept per day, next to the day's totals, so that they age with them.
const SETTLE_OUTBOX_SCRIPT = `
local removed = redis.call('LREM', KEYS[1], 1, ARGV[1])
if removed == 1 and ARGV[2] == '1' then
  redis.call('HINCRBY', KEYS[2], 'records', tonumber(ARGV[3]))
  redis.call('HINCRBY', KEYS[2], 'objects', tonumber(ARGV[4]))
  for index = 6, #ARGV, 2 do
    redis.call('HINCRBY', KEYS[2], '${STATS_TYPE_FIELD_PREFIX}' .. ARGV[index], tonumber(ARGV[index + 1]))
  end
  redis.call('EXPIRE', KEYS[2], tonumber(ARGV[5]))
end
return removed
`;

export interface PulseOutboxEntry extends PulseOutboxItem {
  raw: string;
}

const isPulseOutboxItem = (value: PulseOutboxItem | null): value is PulseOutboxItem => {
  return !!value && typeof value.batch === 'object' && value.batch !== null && typeof value.stats === 'object' && value.stats !== null;
};

// A claimed batch stays in Redis until redisSettlePulseOutboxEntry: a run that stops or fails before XTM Hub answered
// leaves it to the next run, so a pending contribution is never lost.
export const redisClaimPulseOutbox = async (): Promise<PulseOutboxEntry[]> => {
  const raw = ((await getClientBase().eval(CLAIM_OUTBOX_SCRIPT, 2, OUTBOX_KEY, OUTBOX_INFLIGHT_KEY)) as string[] | null) ?? [];
  const entries: PulseOutboxEntry[] = [];
  for (let index = 0; index < raw.length; index += 1) {
    const item = parseJson<PulseOutboxItem>(raw[index], OUTBOX_KEY);
    if (isPulseOutboxItem(item)) {
      entries.push({ raw: raw[index], batch: item.batch, stats: item.stats, policy: item.policy });
    } else {
      await getClientBase().lrem(OUTBOX_INFLIGHT_KEY, 1, raw[index]);
    }
  }
  return entries;
};

// Once XTM Hub answered the batch: accepted, its records count in the contribution statistics; refused for good or
// past the accepted salt days, it is dropped without counting.
export const redisSettlePulseOutboxEntry = async (entry: PulseOutboxEntry, accepted: boolean) => {
  const typeArgs = Object.entries(entry.stats.by_type).flatMap(([entityType, records]) => [entityType, String(records)]);
  await getClientBase().eval(
    SETTLE_OUTBOX_SCRIPT,
    2,
    OUTBOX_INFLIGHT_KEY,
    `${STATS_DAY_PREFIX}${entry.batch.day}`,
    entry.raw,
    accepted ? '1' : '0',
    String(entry.stats.records),
    String(entry.stats.objects),
    String(STATS_TTL_SECONDS),
    ...typeArgs,
  );
};

// Opting out: nothing pending may leave afterwards.
export const redisDiscardPulseOutbox = async () => {
  await getClientBase().del(OUTBOX_KEY, OUTBOX_INFLIGHT_KEY);
};
// endregion

// region operational state and statistics
export interface PulseOperationalState {
  last_push_at?: string;
  last_refresh_at?: string;
  // How many objects in scope the next nightly refresh skips: the ones the previous runs covered.
  refresh_offset?: string;
  last_error?: string;
  // 'true' once XTM Hub answered contribution_required to a contributing platform, until its next accepted push.
  contribution_lapsed?: string;
  // 'true' once XTM Hub accepted a contribution of the platform since it enabled the contribution or purged it: XTM Hub
  // grants the full reads to a platform that contributed, never to one that only asked to.
  contribution_accepted?: string;
  preview_refresh_at?: string;
  // How many objects in scope the next preview pass skips: the ones the previous passes covered.
  preview_offset?: string;
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

export const redisGetPulseContributionStats = async (days: string[]) => {
  const client = getClientBase();
  const byType = new Map<string, number>();
  const perDay = await Promise.all(days.map(async (day) => {
    const values = (await client.hgetall(`${STATS_DAY_PREFIX}${day}`)) ?? {};
    Object.entries(values).filter(([field]) => field.startsWith(STATS_TYPE_FIELD_PREFIX)).forEach(([field, records]) => {
      const entityType = field.slice(STATS_TYPE_FIELD_PREFIX.length);
      byType.set(entityType, (byType.get(entityType) ?? 0) + Number(records));
    });
    return { day, records: Number(values.records ?? 0), objects: Number(values.objects ?? 0) };
  }));
  // Over the same days as the totals
  return {
    days: perDay,
    byType: Array.from(byType.entries()).map(([entityType, records]) => ({ entity_type: entityType, records })),
  };
};

const activityKeys = (days: string[]) => days.flatMap((day) => [`${ACTIVITY_PREFIX}${day}`, `${ACTIVITY_PREFIX}${day}${TAKEN_SUFFIX}`]);

export const redisClearPulseContributionState = async (days: string[]) => {
  const client = getClientBase();
  await client.del(STATS_TYPE_KEY, OUTBOX_KEY, OUTBOX_INFLIGHT_KEY, CURSOR_KEY, TRENDING_NOTIFIED_KEY, ...activityKeys(days), ...days.map((day) => `${STATS_DAY_PREFIX}${day}`));
};
// endregion

// region activity the database cannot rebuild (sightings seen again), kept per UTC day
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

// Atomically moves entries of the activity of a day into its taken set until the taken set holds *limit* entries -
// what a run that failed before its acknowledgement left there counts - and returns the whole taken set. The entries
// left in the activity wait for the next runs.
const TAKE_ACTIVITY_SCRIPT = `
local activity = KEYS[1]
local taken = KEYS[2]
local missing = tonumber(ARGV[1]) - redis.call('HLEN', taken)
local cursor = '0'
while missing > 0 do
  local scan = redis.call('HSCAN', activity, cursor, 'COUNT', math.max(missing, 10))
  cursor = scan[1]
  local values = scan[2]
  for index = 1, #values, 2 do
    if missing > 0 then
      redis.call('HINCRBY', taken, values[index], values[index + 1])
      redis.call('HDEL', activity, values[index])
      missing = missing - 1
    end
  end
  if cursor == '0' then
    break
  end
end
if redis.call('EXISTS', taken) == 1 then
  redis.call('EXPIRE', taken, tonumber(ARGV[2]))
end
return redis.call('HGETALL', taken)
`;

// The activity recorded on *day* and not acknowledged yet, at most *limit* entries (more only when a run that failed
// before its acknowledgement left more under a larger limit). It stays in Redis until redisCommitPulseWindow writes the
// batches built from it to the outbox: sightings seen again cannot be rebuilt from the database, so a run that stops
// before hands them to the next run.
export const redisTakePulseActivity = async (day: string, limit: number): Promise<PulseExternalActivity[]> => {
  const key = `${ACTIVITY_PREFIX}${day}`;
  const script = await getClientBase().eval(TAKE_ACTIVITY_SCRIPT, 2, key, `${key}${TAKEN_SUFFIX}`, Math.max(0, Math.floor(limit)), ACTIVITY_TTL_SECONDS);
  const flat = (script as string[] | null) ?? [];
  const activity: PulseExternalActivity[] = [];
  for (let index = 0; index + 1 < flat.length; index += 2) {
    const [entityId, eventKind] = flat[index].split('|');
    activity.push({ entityId, eventKind: eventKind as PulseEventKind, count: Number(flat[index + 1]) });
  }
  return activity;
};

// Opting out: nothing recorded before may leave afterwards.
export const redisDiscardPulseActivity = async (days: string[]) => {
  await getClientBase().del(...activityKeys(days));
};
// endregion

// region trending notifications memory
// Members are "<trigger id>|<object id>" pairs.
export const redisFilterNewlyTrending = async (members: string[], memoryDays: number): Promise<string[]> => {
  if (members.length === 0) {
    return [];
  }
  const client = getClientBase();
  const now = Date.now();
  await client.zremrangebyscore(TRENDING_NOTIFIED_KEY, '-inf', now - memoryDays * 24 * 3600 * 1000);
  const scores = await client.zmscore(TRENDING_NOTIFIED_KEY, ...members);
  return members.filter((_, index) => scores[index] === null);
};

export const redisMarkTrendingNotified = async (members: string[]) => {
  if (members.length === 0) {
    return;
  }
  const now = Date.now();
  await getClientBase().zadd(TRENDING_NOTIFIED_KEY, ...members.flatMap((member) => [now, member]));
};
// endregion
