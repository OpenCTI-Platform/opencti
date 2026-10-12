import type { AuthContext } from '../types/user';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { logApp } from '../config/conf';
import { UnsupportedError } from '../config/errors';
import { elLoadById } from '../database/engine';
import { READ_INDEX_HISTORY } from '../database/utils';
import { ENTITY_TYPE_WORK } from '../schema/internalObject';
import { redisAcquireWorkCompletionHooksFlag, redisDeleteWorkTouchedElements } from '../database/redis';

export interface CompletedWork {
  id: string;
  event_type?: string;
  touched_ids?: string[];
  touched_ids_truncated?: boolean;
  investigation_id?: string;
  draft_context?: string;
  errors?: unknown[];
  event_source_id?: string;
  [key: string]: unknown;
}

export interface WorkCompletionHook {
  id: string;
  eventTypes: string[];
  handler: (context: AuthContext, work: CompletedWork) => Promise<void>;
}

const hooks = new Map<string, WorkCompletionHook>();

/**
 * Register a hook to run once when a work of one of its event types completes.
 * @throws when a hook with the same id is already registered
 */
export const registerWorkCompletionHook = (hook: WorkCompletionHook) => {
  if (hooks.has(hook.id)) {
    throw UnsupportedError('Work completion hook already registered', { id: hook.id });
  }
  hooks.set(hook.id, hook);
};

/**
 * Remove a previously registered completion hook (used by tests).
 */
export const unregisterWorkCompletionHook = (id: string) => {
  hooks.delete(id);
};

/**
 * Complete a work: always clear its touched set, then, if some hook matches its
 * event type, reload the work and, only if this caller wins the completion flag,
 * run every matching hook. The reload comes before the flag so that a failed
 * reload does not consume the once-only flag, letting another completion path retry.
 * A failed cleanup is only logged (the keys expire through their TTL) and never skips the hooks.
 * A failing hook is logged and does not prevent the others from running.
 * Hooks run once, at the first completion: they see the touched ids as persisted by that completion,
 * not the ids a later completion of the same work may add.
 */
export const runWorkCompletion = async (workId: string, eventType: string | undefined) => {
  // Ids are already persisted on the work at this point, the Redis set is no longer needed
  try {
    await redisDeleteWorkTouchedElements([workId]);
  } catch (err) {
    logApp.warn('[WORK] Unable to clean the touched elements of a completed work', { workId, cause: err });
  }
  const matching = Array.from(hooks.values()).filter((hook) => eventType && hook.eventTypes.includes(eventType));
  if (matching.length === 0) {
    return;
  }
  // A reload failure throws here, before the flag is taken, so the work stays retryable
  const context = executionContext('work_completion');
  const work = await elLoadById(context, SYSTEM_USER, workId, { type: ENTITY_TYPE_WORK, indices: READ_INDEX_HISTORY });
  if (!work) {
    return;
  }
  // Several completion paths (and nodes) can observe the same completion: only one dispatches
  const isOwner = await redisAcquireWorkCompletionHooksFlag(workId);
  if (!isOwner) {
    return;
  }
  const completedWork = { ...work, id: workId } as CompletedWork;
  for (let index = 0; index < matching.length; index += 1) {
    const hook = matching[index];
    try {
      await hook.handler(context, completedWork);
    } catch (err) {
      logApp.error('[WORK] Completion hook failed', { hookId: hook.id, workId, cause: err });
    }
  }
};

/**
 * Fire-and-forget wrapper around runWorkCompletion: non-blocking, so the request
 * that completed the work does not wait for the hooks. Errors are only logged.
 */
export const dispatchWorkCompletion = (workId: string, eventType: string | undefined) => {
  runWorkCompletion(workId, eventType)
    .catch((err) => logApp.warn('[WORK] Completion dispatch failed', { workId, cause: err }));
};
