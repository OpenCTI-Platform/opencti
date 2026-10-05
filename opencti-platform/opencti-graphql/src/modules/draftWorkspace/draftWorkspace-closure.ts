import type { AuthContext } from '../../types/user';
import { redisGetDraftForward, redisSetDraftForward, redisSetDraftForwardIfAbsent } from '../../database/redis';

/**
 * Called when a draft is about to be validated or deleted, before its content is read or removed and before the users
 * working in it are moved back to the live context: a module routing users into a draft (Source Intelligence
 * quarantine) moves them to another draft first, so nothing they write lands in a draft that is being closed.
 */
export type DraftClosureHandler = (context: AuthContext, draftId: string) => Promise<void>;

// Forward entry of the last draft of a forwarding chain while it is open, then once it closed with no draft taking over
const DRAFT_FORWARD_OPEN_END = 'open';
const DRAFT_FORWARD_CLOSED_END = 'closed';

export interface DraftForward {
  // Draft the queued work belongs to: the draft itself, or the last of the drafts that successively took over from it
  draftId: string;
  // That draft was closed and no draft took over from it: the work has no draft to be processed in
  closed: boolean;
}

const draftClosureHandlers: DraftClosureHandler[] = [];

export const registerDraftClosureHandler = (handler: DraftClosureHandler) => {
  draftClosureHandlers.push(handler);
};

export const runDraftClosureHandlers = async (context: AuthContext, draftId: string) => {
  for (let i = 0; i < draftClosureHandlers.length; i += 1) {
    await draftClosureHandlers[i](context, draftId);
  }
  // A draft receiving forwarded work that no handler replaced ends its chain: the work still queued for it is refused
  if ((await redisGetDraftForward(draftId)) === DRAFT_FORWARD_OPEN_END) {
    await redisSetDraftForward(draftId, DRAFT_FORWARD_CLOSED_END);
  }
};

/**
 * Starts the forwarding chain of a draft that work is routed into (a quarantine draft), before anything is routed to
 * it: when it closes with no draft taking over, the work still queued for it is refused, whatever the draft cache of
 * the worker's node still says. A draft already in a chain keeps its entry.
 */
export const openDraftForwarding = async (draftId: string) => {
  await redisSetDraftForwardIfAbsent(draftId, DRAFT_FORWARD_OPEN_END);
};

/**
 * Sends the work still queued for a closed draft to the draft that took over from it. A queued message keeps the
 * draft it was pushed for: a worker processing it after the closure must not write into the closed draft.
 */
export const forwardDraftWork = async (closedDraftId: string, nextDraftId: string) => {
  if (closedDraftId !== nextDraftId) {
    await redisSetDraftForward(closedDraftId, nextDraftId);
    await openDraftForwarding(nextDraftId);
  }
};

/**
 * Draft that receives the work queued for a draft: the draft itself, or the last one of the drafts that successively
 * took over from it, however many took over (a loop stops at the last draft before it). A draft reached in several
 * steps is then forwarded straight to that last one, so its next lookups take one step. When that last draft was
 * closed with no draft taking over, the work is flagged as closed: it must be refused, never processed in a closed
 * draft nor in the live knowledge.
 */
export const resolveDraftForward = async (draftId: string): Promise<DraftForward> => {
  const visited = new Set([draftId]);
  let current = draftId;
  let next = await redisGetDraftForward(current);
  while (next && next !== DRAFT_FORWARD_OPEN_END && next !== DRAFT_FORWARD_CLOSED_END && !visited.has(next)) {
    visited.add(next);
    current = next;
    next = await redisGetDraftForward(current);
  }
  if (visited.size > 2) {
    await redisSetDraftForward(draftId, current);
  }
  return { draftId: current, closed: next === DRAFT_FORWARD_CLOSED_END };
};
