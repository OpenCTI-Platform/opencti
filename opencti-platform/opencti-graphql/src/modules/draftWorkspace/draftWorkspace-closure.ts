import { v4 as uuidv4 } from 'uuid';
import type { AuthContext } from '../../types/user';
import { FunctionalError } from '../../config/errors';
import conf, { logApp } from '../../config/conf';
import { wait } from '../../database/utils';
import { redisAddDraftWriter, redisGetDraftForward, redisListDraftWriters, redisRemoveDraftWriter, redisSetDraftForward, redisSetDraftForwardIfAbsent } from '../../database/redis';

/**
 * Called when a draft is about to be validated or deleted, before its content is read or removed and before the users
 * working in it are moved back to the live context: a module routing users into a draft (Source Intelligence
 * quarantine) moves them to another draft first, so nothing they write lands in a draft that is being closed.
 */
export type DraftClosureHandler = (context: AuthContext, draftId: string) => Promise<void>;

// Forward entry of the last draft of a forwarding chain while it is open, then once it closed with no draft taking over
const DRAFT_FORWARD_OPEN_END = 'open';
const DRAFT_FORWARD_CLOSED_END = 'closed';
// Lease of a request writing into a draft of a chain, renewed while the request runs
const DRAFT_WRITER_LEASE_MS = 2 * 60 * 1000;
const DRAFT_WRITER_RENEWAL_MS = 30 * 1000;
// A lease that ended without its release (a node stopped mid-request, or renewals Redis refused) still holds a closure
// back for as long as a search engine request lasts: the request writing may have one in flight, and its next writes
// need Redis to lock what they write
const DRAFT_WRITER_LAPSED_KEPT_MS = conf.get('elasticsearch:request_timeout') || 3600000;
// How long closing a draft waits for the requests still writing into it
const DRAFT_CLOSURE_DRAIN_MS = 30 * 1000;
const DRAFT_CLOSURE_DRAIN_POLL_MS = 200;
// Drafts taking over while a request enters: past this many, the request stays in the last one, which waits for it
const DRAFT_ENTRY_MAX_HOPS = 10;

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

// A request that entered the draft before its work was forwarded ends before the draft content is read or removed.
// The request closing the draft never waits for itself.
const waitForDraftWriters = async (draftId: string, ownWriterId: string | null | undefined) => {
  const deadline = Date.now() + DRAFT_CLOSURE_DRAIN_MS;
  const writersOf = async () => (await redisListDraftWriters(draftId, DRAFT_WRITER_LAPSED_KEPT_MS)).filter((writerId) => writerId !== ownWriterId);
  let writers = await writersOf();
  while (writers.length > 0) {
    if (Date.now() >= deadline) {
      throw FunctionalError('The draft still receives work that started before it was closed, retry in a moment', { draftId, writers: writers.length });
    }
    await wait(DRAFT_CLOSURE_DRAIN_POLL_MS);
    writers = await writersOf();
  }
};

export const runDraftClosureHandlers = async (context: AuthContext, draftId: string) => {
  for (let i = 0; i < draftClosureHandlers.length; i += 1) {
    await draftClosureHandlers[i](context, draftId);
  }
  const forward = await redisGetDraftForward(draftId);
  // A draft receiving forwarded work that no handler replaced ends its chain: the work still queued for it is refused
  if (forward === DRAFT_FORWARD_OPEN_END) {
    await redisSetDraftForward(draftId, DRAFT_FORWARD_CLOSED_END);
  }
  if (forward) {
    await waitForDraftWriters(draftId, context.draft_writer_id);
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

export interface DraftEntry extends DraftForward {
  // Lease the request holds on the draft it writes into until release: none outside a forwarding chain or once refused
  writerId: string | null;
  release: () => Promise<void>;
}

const noLease = async () => {};

// Renews the lease until it is released, however long the request runs: it only ends unreleased when its node stopped
// mid-request or Redis refused the renewals, and then still holds a closure back (see DRAFT_WRITER_LAPSED_KEPT_MS)
const holdLease = (draftId: string, writerId: string) => {
  let renewing: Promise<void> = Promise.resolve();
  const renewal = setInterval(() => {
    renewing = renewing
      .then(() => redisAddDraftWriter(draftId, writerId, DRAFT_WRITER_LEASE_MS, DRAFT_WRITER_LAPSED_KEPT_MS))
      .catch((cause) => logApp.warn('[OPENCTI] Draft lease of a request could not be renewed', { cause, draftId }));
  }, DRAFT_WRITER_RENEWAL_MS);
  renewal.unref?.();
  let released: Promise<void> | undefined;
  return () => {
    clearInterval(renewal);
    // A renewal already sent must not record the lease again after its removal
    released ??= renewing.then(() => redisRemoveDraftWriter(draftId, writerId));
    return released;
  };
};

/**
 * Draft a request works in, resolved like queued work (see resolveDraftForward). In a forwarding chain, the request
 * holds a lease on that draft from before it reads the forward until it is released: a closure forwards the draft
 * first, then waits for the leases, so a request either is waited for or sees the forward and moves to the draft
 * taking over. A draft enters a chain when it is created to receive routed work, so outside a chain no lease is needed.
 * When entering fails, the leases it took are released: no request would release them, and a lease that ended
 * unreleased holds a closure back for as long as a search engine request lasts.
 */
export const enterDraft = async (draftId: string): Promise<DraftEntry> => {
  if (!(await redisGetDraftForward(draftId))) {
    return { draftId, closed: false, writerId: null, release: noLease };
  }
  const writerId = uuidv4();
  // Drafts that may hold a lease of this request
  const leased = new Set<string>();
  const addWriter = async (target: string) => {
    leased.add(target);
    await redisAddDraftWriter(target, writerId, DRAFT_WRITER_LEASE_MS, DRAFT_WRITER_LAPSED_KEPT_MS);
  };
  const removeWriter = async (target: string) => {
    await redisRemoveDraftWriter(target, writerId);
    leased.delete(target);
  };
  try {
    let target = draftId;
    await addWriter(target);
    let forward = await resolveDraftForward(target);
    for (let hop = 0; !forward.closed && forward.draftId !== target && hop < DRAFT_ENTRY_MAX_HOPS; hop += 1) {
      const previous = target;
      target = forward.draftId;
      await addWriter(target);
      await removeWriter(previous);
      forward = await resolveDraftForward(target);
    }
    if (forward.closed) {
      await removeWriter(target);
      return { draftId: forward.draftId, closed: true, writerId: null, release: noLease };
    }
    return { draftId: target, closed: false, writerId, release: holdLease(target, writerId) };
  } catch (error) {
    await Promise.all([...leased].map((target) => redisRemoveDraftWriter(target, writerId)
      .catch((cause) => logApp.warn('[OPENCTI] Draft lease of a request that could not enter its draft could not be released', { cause, draftId: target }))));
    throw error;
  }
};
