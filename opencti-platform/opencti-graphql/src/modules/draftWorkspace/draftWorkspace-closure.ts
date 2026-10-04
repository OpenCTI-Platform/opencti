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

const DRAFT_FORWARD_MAX_HOPS = 10;

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
 * took over from it.
 */
export const resolveDraftForward = async (draftId: string) => {
  let current = draftId;
  for (let hop = 0; hop < DRAFT_FORWARD_MAX_HOPS; hop += 1) {
    const next = await redisGetDraftForward(current);
    if (!next || next === draftId) {
      return current;
    }
    current = next;
  }
  return current;
};
