import { getClientBase } from '../../../database/redis';
import { logApp } from '../../../config/conf';
import type { PulseEventKind, PulseOutboxItem } from './pulse-types';

// The {pulse} hash tag keeps every key on one Redis cluster slot, as some commands below touch several keys.
const SALT_PREFIX = '{pulse}:salt:';
const ENTITY_LOOKUP_PREFIX = '{pulse}:entity:';
const RESPONSE_PREFIX = '{pulse}:response:';
const CURSOR_KEY = '{pulse}:cursor';
const ADMISSION_KEY = '{pulse}:admission';
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
const SIGHTING_PENDING_KEY = '{pulse}:sightings:pending';
const SIGHTING_COUNTED_PREFIX = '{pulse}:sightings:counted:';
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

export const redisDeletePulseResponse = async (cacheKey: string) => {
  await getClientBase().del(`${RESPONSE_PREFIX}${cacheKey}`);
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

// The scopes and marking exclusions in force until a widening of the settings: the activity before that instant is
// collected under them, never under the wider ones. It outlives the activity it bounds, never contributed past 3 days.
export interface PulseAdmission {
  until: string;
  scopes: string[];
  excludedMarkingIds: string[];
}

export const redisGetPulseAdmission = async (): Promise<PulseAdmission | null> => {
  return parseJson<PulseAdmission>(await getClientBase().get(ADMISSION_KEY), ADMISSION_KEY);
};

export const redisSetPulseAdmission = async (admission: PulseAdmission) => {
  await getClientBase().set(ADMISSION_KEY, JSON.stringify(admission), 'EX', ACTIVITY_TTL_SECONDS);
};

export const redisDiscardPulseAdmission = async () => {
  await getClientBase().del(ADMISSION_KEY);
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

// KEYS: generation, outbox, cursor, the totals of the sightings waiting for their window, the counted totals and the
// activity of the day, then the activity keys to acknowledge. ARGV: the generation of the cycle, the cursor, the number
// of batches, the number of sightings, the TTLs of the counted totals and of the activity, the batches, then one
// (id, count read, activity field) triple per sighting the window read.
// A sighting seen again while its window was collected raised the total its hook kept: what the window read missed is
// added to the activity of the day, and the total counted so far is kept for the hooks that run after the commit.
const COMMIT_WINDOW_SCRIPT = `
if (redis.call('GET', KEYS[1]) or '0') ~= ARGV[1] then
  return 0
end
local batches = tonumber(ARGV[3])
local sightings = tonumber(ARGV[4])
local first = 7
for index = first, first + batches - 1 do
  redis.call('RPUSH', KEYS[2], ARGV[index])
end
local start = first + batches
for index = start, start + sightings * 3 - 1, 3 do
  local count = tonumber(ARGV[index + 1])
  local seen = tonumber(redis.call('HGET', KEYS[4], ARGV[index]) or '0')
  redis.call('HDEL', KEYS[4], ARGV[index])
  if seen > count then
    redis.call('HINCRBY', KEYS[6], ARGV[index + 2], seen - count)
    redis.call('EXPIRE', KEYS[6], tonumber(ARGV[6]))
  end
  redis.call('HSET', KEYS[5], ARGV[index], math.max(seen, count))
end
if sightings > 0 then
  redis.call('EXPIRE', KEYS[5], tonumber(ARGV[5]))
end
redis.call('SET', KEYS[3], ARGV[2])
for index = 7, #KEYS do
  redis.call('DEL', KEYS[index])
end
return 1
`;

// A sighting a contribution window read: its id, the count read and the activity field of its sighted object.
export interface PulseWindowSighting {
  id: string;
  count: number;
  entityId: string;
  eventKind: PulseEventKind;
}

// The totals counted for the sightings a window read are kept long enough for the hooks of the upserts that raced with
// the window; past it, the increase an upsert reports is exact.
const SIGHTING_COUNTED_TTL_SECONDS = 2 * 24 * 3600;
const sightingCountedKey = (day: string) => `${SIGHTING_COUNTED_PREFIX}${day}`;
const utcToday = () => new Date().toISOString().slice(0, 10);
const utcYesterday = () => new Date(Date.now() - 24 * 3600 * 1000).toISOString().slice(0, 10);

// The batches of a contribution window, the cursor after it and the acknowledgement of the activity taken from Redis,
// in one script (every key shares the {pulse} slot): all of them are written, or none when the configuration changed
// since the cycle started. The outbox is never trimmed: a run whose pending batches XTM Hub did not answer collects no
// new window, and a batch whose salt day XTM Hub no longer accepts is dropped when claimed, so it holds at most one
// window beyond the accepted days.
export const redisCommitPulseWindow = async (
  items: PulseOutboxItem[],
  cursor: string,
  ackDays: string[],
  generation: string,
  sightings: PulseWindowSighting[] = [],
): Promise<boolean> => {
  const ackKeys = ackDays.map((day) => `${ACTIVITY_PREFIX}${day}${TAKEN_SUFFIX}`);
  const today = utcToday();
  const committed = await getClientBase().eval(
    COMMIT_WINDOW_SCRIPT,
    6 + ackKeys.length,
    CONFIG_GENERATION_KEY,
    OUTBOX_KEY,
    CURSOR_KEY,
    SIGHTING_PENDING_KEY,
    sightingCountedKey(today),
    `${ACTIVITY_PREFIX}${today}`,
    ...ackKeys,
    generation,
    cursor,
    items.length,
    sightings.length,
    SIGHTING_COUNTED_TTL_SECONDS,
    ACTIVITY_TTL_SECONDS,
    ...items.map((item) => JSON.stringify(item)),
    ...sightings.flatMap((sighting) => [sighting.id, Math.max(0, Math.floor(sighting.count)), `${sighting.entityId}|${sighting.eventKind}`]),
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
  // Where the scan under the current digest day started when that day began mid-scan: once the end of the scope is
  // reached, the scan goes on from the start up to there.
  preview_scan_start?: string;
  preview_digest_day?: string;
  preview_digest_items?: string;
  preview_matched?: string;
  preview_since?: string;
  // 'registration', 'opening', 'network' or 'scope' while a cleanup of the community data that failed waits for the
  // next manager cycle, with the JSON scope ({ entityTypes, markingIds }) of a partial one.
  cleanup_pending?: string;
  cleanup_scope?: string;
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

// The activity of the days with what a run took from it, and the sighting totals that can still turn into activity.
const activityKeys = (days: string[]) => [
  ...days.flatMap((day) => [`${ACTIVITY_PREFIX}${day}`, `${ACTIVITY_PREFIX}${day}${TAKEN_SUFFIX}`, sightingCountedKey(day)]),
  SIGHTING_PENDING_KEY,
];

export const redisClearPulseContributionState = async (days: string[]) => {
  const client = getClientBase();
  await client.del(STATS_TYPE_KEY, OUTBOX_KEY, OUTBOX_INFLIGHT_KEY, CURSOR_KEY, ADMISSION_KEY, TRENDING_NOTIFIED_KEY, ...activityKeys(days), ...days.map((day) => `${STATS_DAY_PREFIX}${day}`));
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

// KEYS: cursor, totals of the sightings waiting for their window, counted totals of today and of yesterday, activity of
// today. ARGV: sighting id, its creation date, the oldest date a window collects without a cursor (the later of the
// consent and of the oldest accepted day; ISO dates, compared as text), its new total, the increase, the activity field,
// then the TTLs of the waiting totals, the counted totals and the activity. Decided against the cursor in the same
// script as the commit of a window, so each increase counts once:
// - created at or after the start of the next window: its window reads the total, and the highest total its upserts
//   reached is kept for the commit of that window, which adds what the read missed;
// - otherwise: the increase is activity, or, while the total counted by a recent window is known, what exceeds it.
const RECORD_SIGHTING_SCRIPT = `
local bound = ARGV[3]
local cursor = redis.call('GET', KEYS[1])
if cursor and cursor > bound then
  bound = cursor
end
if ARGV[2] ~= '' and ARGV[2] >= bound then
  if tonumber(ARGV[4]) > tonumber(redis.call('HGET', KEYS[2], ARGV[1]) or '0') then
    redis.call('HSET', KEYS[2], ARGV[1], ARGV[4])
  end
  redis.call('EXPIRE', KEYS[2], tonumber(ARGV[7]))
  return 0
end
local total = tonumber(ARGV[4])
local delta = tonumber(ARGV[5])
local counted = redis.call('HGET', KEYS[3], ARGV[1]) or redis.call('HGET', KEYS[4], ARGV[1])
if counted then
  delta = total - tonumber(counted)
  redis.call('HSET', KEYS[3], ARGV[1], math.max(total, tonumber(counted)))
  redis.call('EXPIRE', KEYS[3], tonumber(ARGV[8]))
end
if delta <= 0 then
  return 0
end
redis.call('HINCRBY', KEYS[5], ARGV[6], delta)
redis.call('EXPIRE', KEYS[5], tonumber(ARGV[9]))
return delta
`;

export interface PulseSightingIncrease {
  id: string;
  createdAt: string;
  oldestCollected: string;
  total: number;
  increase: number;
  entityId: string;
  eventKind: PulseEventKind;
}

// Records a sighting seen again; answers the activity it added (0 while its window has still to read it).
export const redisRecordPulseSightingIncrease = async (sighting: PulseSightingIncrease): Promise<number> => {
  const result = await getClientBase().eval(
    RECORD_SIGHTING_SCRIPT,
    5,
    CURSOR_KEY,
    SIGHTING_PENDING_KEY,
    sightingCountedKey(utcToday()),
    sightingCountedKey(utcYesterday()),
    `${ACTIVITY_PREFIX}${utcToday()}`,
    sighting.id,
    sighting.createdAt,
    sighting.oldestCollected,
    Math.max(0, Math.floor(sighting.total)),
    Math.max(0, Math.floor(sighting.increase)),
    `${sighting.entityId}|${sighting.eventKind}`,
    ACTIVITY_TTL_SECONDS,
    SIGHTING_COUNTED_TTL_SECONDS,
    ACTIVITY_TTL_SECONDS,
  );
  return Number(result ?? 0);
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
