import conf from '../../config/conf';
import { getClientBase } from '../../database/redis';

// Sorted set of containers waiting for a timeline regeneration, scored by the time they become due.
// The queue and the in-flight set share a hash tag: the claim script reads both, also on a Redis cluster.
const TIMELINE_QUEUE_KEY = '{timeline_regeneration}_queue';
// Debounce: the first change of a container schedules its regeneration, the following changes
// arriving before the due time are absorbed by the same regeneration.
export const TIMELINE_DEBOUNCE_MS = conf.get('timeline_manager:debounce_ms') ?? 10000;

/**
 * Schedule the regeneration of the given containers. Already scheduled containers keep their
 * due time (NX), which bounds the latency under continuous activity.
 */
export const enqueueTimelineRegeneration = async (containerIds: string[], delayMs = TIMELINE_DEBOUNCE_MS) => {
  const ids = Array.from(new Set(containerIds.filter((id) => !!id)));
  if (ids.length === 0) return;
  const dueAt = Date.now() + delayMs;
  const args = ids.flatMap((id) => [dueAt, id]);
  await getClientBase().zadd(TIMELINE_QUEUE_KEY, 'NX', ...(args as [number, string]));
};

// Claimed containers, scored by the end of their lease: a claim is only dropped once its regeneration was handled
const TIMELINE_IN_FLIGHT_KEY = '{timeline_regeneration}_in_flight';
// Longer than any bounded regeneration; a claim whose manager stopped before handling it is due again after it
export const TIMELINE_CLAIM_LEASE_MS = conf.get('timeline_manager:claim_lease_ms') ?? 900000;
const RECLAIM_BATCH = 1000;
// The due range is read by chunks, and at most this many members per claim whatever the number in flight
const CLAIM_SCAN_CHUNK = 100;
const CLAIM_SCAN_MAX = 2000;

// One atomic step: expired leases go back to the queue (a newer schedule keeps its due time), then the due
// containers move from the queue to the in-flight set. A schedule added while a claim runs is never absorbed by it:
// a container still in flight under its lease stays queued until that claim is acknowledged or expires, so it is never
// regenerated twice at once and no acknowledgement removes the lease of a later claim. The due range is read by
// chunks past the in-flight members it skips, so that a batch still fills up to its limit; a claimed member leaves the
// queue, so the next chunk starts after the skipped ones only.
const CLAIM_DUE_SCRIPT = `
local expired = redis.call('ZRANGEBYSCORE', KEYS[2], '-inf', ARGV[1], 'LIMIT', 0, tonumber(ARGV[4]))
for _, id in ipairs(expired) do
  redis.call('ZREM', KEYS[2], id)
  redis.call('ZADD', KEYS[1], 'NX', ARGV[1], id)
end
local limit = tonumber(ARGV[2])
local chunk = tonumber(ARGV[5])
local maxScanned = tonumber(ARGV[6])
local claimed = {}
local skipped = 0
local scanned = 0
while #claimed < limit and scanned < maxScanned do
  local due = redis.call('ZRANGEBYSCORE', KEYS[1], '-inf', ARGV[1], 'LIMIT', skipped, chunk)
  if #due == 0 then break end
  for _, id in ipairs(due) do
    if #claimed >= limit then break end
    if redis.call('ZSCORE', KEYS[2], id) then
      skipped = skipped + 1
    else
      redis.call('ZREM', KEYS[1], id)
      redis.call('ZADD', KEYS[2], ARGV[3], id)
      table.insert(claimed, id)
    end
  end
  scanned = scanned + #due
end
return claimed
`;

/** Containers claimed by one call, all under the same lease: the end of the lease is the token that acknowledges them. */
export interface TimelineRegenerationClaims {
  containerIds: string[];
  lease: number;
}

/**
 * Claim at most `limit` due containers. A container is claimed by moving it from the queue to the in-flight set
 * under a lease, so two consumers can never process the same container from the same scheduling, and a claim is
 * never lost: until `acknowledgeTimelineRegeneration`, an expired lease makes the container due again.
 */
export const claimDueTimelineRegenerations = async (limit: number): Promise<TimelineRegenerationClaims> => {
  const nowTime = Date.now();
  const lease = nowTime + TIMELINE_CLAIM_LEASE_MS;
  if (limit <= 0) return { containerIds: [], lease };
  const claimed = await getClientBase().eval(
    CLAIM_DUE_SCRIPT,
    2,
    TIMELINE_QUEUE_KEY,
    TIMELINE_IN_FLIGHT_KEY,
    nowTime,
    limit,
    lease,
    RECLAIM_BATCH,
    CLAIM_SCAN_CHUNK,
    CLAIM_SCAN_MAX,
  );
  return { containerIds: Array.isArray(claimed) ? claimed.map((id) => String(id)) : [], lease };
};

// Compare and delete in one atomic step: a claim is released only by its own claimant. A worker that outlived its lease
// finds a later claim of the container (a later lease end) and leaves it in flight
const ACKNOWLEDGE_SCRIPT = `
local lease = redis.call('ZSCORE', KEYS[1], ARGV[1])
if lease and tonumber(lease) == tonumber(ARGV[2]) then
  return redis.call('ZREM', KEYS[1], ARGV[1])
end
return 0
`;

/** Release the claim of a container once its regeneration succeeded or its retry was scheduled; false when it was claimed again since. */
export const acknowledgeTimelineRegeneration = async (containerId: string, lease: number): Promise<boolean> => {
  const released = await getClientBase().eval(ACKNOWLEDGE_SCRIPT, 1, TIMELINE_IN_FLIGHT_KEY, containerId, lease);
  return Number(released) === 1;
};

// Failed regenerations are retried with an exponential backoff, then left to the next change or the nightly pass
const TIMELINE_ATTEMPTS_KEY = 'timeline_regeneration_attempts';
export const TIMELINE_MAX_RETRIES = 3;

export const retryDelayMs = (attempt: number) => TIMELINE_DEBOUNCE_MS * 2 ** attempt;

/** Schedule a new attempt of a failed regeneration; false once the retries of the container are exhausted. */
export const retryTimelineRegeneration = async (containerId: string): Promise<boolean> => {
  const attempt = await getClientBase().hincrby(TIMELINE_ATTEMPTS_KEY, containerId, 1);
  if (attempt > TIMELINE_MAX_RETRIES) {
    await getClientBase().hdel(TIMELINE_ATTEMPTS_KEY, containerId);
    return false;
  }
  await enqueueTimelineRegeneration([containerId], retryDelayMs(attempt));
  return true;
};

export const clearTimelineRegenerationAttempts = async (containerId: string) => {
  await getClientBase().hdel(TIMELINE_ATTEMPTS_KEY, containerId);
};

export const countPendingTimelineRegenerations = async (): Promise<number> => {
  return getClientBase().zcard(TIMELINE_QUEUE_KEY);
};

const TIMELINE_CONSISTENCY_KEY = 'timeline_consistency_last_run';

export const getTimelineConsistencyLastRun = async (): Promise<number | null> => {
  const value = await getClientBase().get(TIMELINE_CONSISTENCY_KEY);
  return value ? parseInt(value, 10) : null;
};

export const setTimelineConsistencyLastRun = async (time: number) => {
  await getClientBase().set(TIMELINE_CONSISTENCY_KEY, String(time));
};
