import conf from '../../config/conf';
import { getClientBase } from '../../database/redis';

// Sorted set of containers waiting for a timeline regeneration, scored by the time they become due.
const TIMELINE_QUEUE_KEY = 'timeline_regeneration_queue';
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

/**
 * Claim at most `limit` due containers. A container is claimed by removing it from the queue,
 * so two consumers can never process the same container from the same scheduling.
 */
export const claimDueTimelineRegenerations = async (limit: number): Promise<string[]> => {
  const due = await getClientBase().zrangebyscore(TIMELINE_QUEUE_KEY, '-inf', Date.now(), 'LIMIT', 0, limit);
  const claimed: string[] = [];
  for (let index = 0; index < due.length; index += 1) {
    const removed = await getClientBase().zrem(TIMELINE_QUEUE_KEY, due[index]);
    if (removed === 1) claimed.push(due[index]);
  }
  return claimed;
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
