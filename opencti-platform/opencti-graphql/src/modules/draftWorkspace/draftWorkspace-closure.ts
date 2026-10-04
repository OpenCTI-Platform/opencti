import type { AuthContext } from '../../types/user';
import { redisGetDraftForward, redisSetDraftForward } from '../../database/redis';

/**
 * Called when a draft is about to be validated or deleted, before its content is read or removed and before the users
 * working in it are moved back to the live context: a module routing users into a draft (Source Intelligence
 * quarantine) moves them to another draft first, so nothing they write lands in a draft that is being closed.
 */
export type DraftClosureHandler = (context: AuthContext, draftId: string) => Promise<void>;

const draftClosureHandlers: DraftClosureHandler[] = [];

export const registerDraftClosureHandler = (handler: DraftClosureHandler) => {
  draftClosureHandlers.push(handler);
};

export const runDraftClosureHandlers = async (context: AuthContext, draftId: string) => {
  for (let i = 0; i < draftClosureHandlers.length; i += 1) {
    await draftClosureHandlers[i](context, draftId);
  }
};

/**
 * Sends the work still queued for a closed draft to the draft that took over from it. A queued message keeps the
 * draft it was pushed for: a worker processing it after the closure must not write into the closed draft.
 */
export const forwardDraftWork = async (closedDraftId: string, nextDraftId: string) => {
  if (closedDraftId !== nextDraftId) {
    await redisSetDraftForward(closedDraftId, nextDraftId);
  }
};

/**
 * Draft that receives the work queued for a draft: the draft itself, or the last one of the drafts that successively
 * took over from it, however many took over (a loop stops at the last draft before it). A draft reached in several
 * steps is then forwarded straight to that last one, so its next lookups take one step.
 */
export const resolveDraftForward = async (draftId: string) => {
  const visited = new Set([draftId]);
  let current = draftId;
  let next = await redisGetDraftForward(current);
  while (next && !visited.has(next)) {
    visited.add(next);
    current = next;
    next = await redisGetDraftForward(current);
  }
  if (visited.size > 2) {
    await redisSetDraftForward(draftId, current);
  }
  return current;
};
