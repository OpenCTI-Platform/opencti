// POC ingestion sequencer (task 0040 defect 1, multi_writer): relations against a concurrent merge of
// their endpoints. Under multi_writer a batch does not lock its relations' endpoints across platforms
// (computeOwnLockKeys: they only receive commuting ref appends), so a merge on another platform could read
// the source's dependencies before the relation was written, then delete the source: the relation was
// lost with it or left on the deleted source (0-6 per mix285k run). Shared / exclusive on the endpoints:
// a batch SHARES the endpoints of the relations it writes until its flush is refreshed (relations never
// exclude each other, hot endpoints stay free), renewing them while it runs; a merge MARKS its sources
// before reading their dependencies and waits for the other holders. A share on a marked entity is refused
// with a LOCK_ERROR: the group starts a new cycle and resolves to the merge target. The mark outlives the
// merge (10 min) so a platform still resolving the source from its identity map is refused too.
// Scope: stix-core relationships created through createRelationRaw. The ref relations an entity carries
// (object, created-by, markings, labels, external references, written as its inner relations) are not
// shared: a ref written on another platform during a merge of its target can still be lost or left on
// the deleted source, as with the workers. Known gap, to measure on a bigger corpus before deciding.
import { randomUUID } from 'node:crypto';
import conf, { logApp } from '../../config/conf';
import { LockTimeoutError } from '../../config/errors';
import {
  bumpLockStamps,
  redisEndpointShareHolders,
  redisMarkMergeSources,
  redisReleaseEndpointShares,
  redisRenewEndpointShares,
  redisShareEndpoints,
  redisUnmarkMergeSources,
} from '../redis';
import type { AuthContext } from '../../types/user';
import { getCurrentBatchLock, type SequencerBatchLock } from './sequencer-batch-lock';
import { SEQUENCER_CONFIG } from './sequencer-config';
import { DEDUP_STAMP_TTL_S, relationDedupLockKey } from './sequencer-multi-writer';

// a share outlives a dead holder by the batch lock's own bound; a live batch renews it three times per bound
const SHARE_TTL_MS = Number(conf.get('app:concurrency:max_ttl') ?? 60000);
const SHARE_RENEW_MS = Math.max(1000, Math.floor(SHARE_TTL_MS / 3));
const MERGE_MARK_TTL_MS = 10 * 60 * 1000;
// a merge outside a batch waits for the shares to go: a live batch releases them after its flush, a dead
// one lets them expire within SHARE_TTL_MS
const MERGE_WAIT_MAX_MS = SHARE_TTL_MS + 5000;
// a merge applied by a batch holds that batch's lock and shares: it never waits long (its platform would
// stall, two such merges would wait on each other), its group starts a new cycle instead. Two such merges
// sharing each other's sources can fail and replan in turn until their timing differs: no cap (POC).
const MERGE_WAIT_APPLYING_MS = 2000;
const MERGE_WAIT_POLL_MS = 25;

type EndpointShares = NonNullable<SequencerBatchLock['shares']>;

export const newEndpointShares = (): EndpointShares => ({ holder: randomUUID(), ids: new Set() });

// The ids of a LOCK_ERROR refused because another platform merges (or merged) them away
export const mergedSourceKeys = (error: any): string[] => {
  const keys = error?.extensions?.data?.mergedSources ?? error?.data?.mergedSources;
  return Array.isArray(keys) ? keys.filter((key: unknown): key is string => typeof key === 'string' && key.length > 0) : [];
};

// Share ids for the current batch: those already shared are skipped, the refused ones are returned
const share = async (shares: EndpointShares, ids: string[]): Promise<string[]> => {
  const missing = [...new Set(ids.filter((id) => typeof id === 'string' && id.length > 0 && !shares.ids.has(id)))];
  if (missing.length === 0) return [];
  const refused = await redisShareEndpoints(shares.holder, missing, SHARE_TTL_MS);
  const refusedSet = new Set(refused);
  missing.filter((id) => !refusedSet.has(id)).forEach((id) => shares.ids.add(id));
  return refused;
};

// Loop, after the batch lock: the endpoints the plan resolved, in one round trip. A refused one is left
// to the apply-time share, which fails the relation's group.
export const preShareEndpoints = async (shares: EndpointShares, ids: string[]): Promise<void> => {
  await share(shares, ids);
};

// createRelationRaw, before its lock site: the relation's resolved endpoints, under an applying batch.
// A refused id is no lock key of the group (nothing to wait for): the loop evicts it and plans again.
export const shareRelationEndpoints = async (context: AuthContext, ids: string[]): Promise<void> => {
  if (!SEQUENCER_CONFIG.multiWriter || context.sequencer?.scope !== 'applying') return;
  const shares = getCurrentBatchLock()?.shares;
  if (!shares) return;
  const refused = await share(shares, ids);
  if (refused.length > 0) throw LockTimeoutError({ participantIds: [], mergedSources: refused }, 'Relation endpoint merged by another platform');
};

// Loop, while the batch runs: its shares follow its lock, which is extended past SHARE_TTL_MS when needed.
// Returns the stop function. A share lost to failed renewals for longer than SHARE_TTL_MS is not reported:
// a merge may then proceed under a batch still writing onto its source (Redis down that long, POC).
export const startEndpointShareRenewal = (shares: EndpointShares | undefined): (() => void) => {
  if (!shares) return () => {};
  const timer = setInterval(() => {
    redisRenewEndpointShares(shares.holder, Array.from(shares.ids), SHARE_TTL_MS)
      .catch((err) => logApp.warn('[SEQUENCER] relation endpoint shares not renewed, retried next period', { cause: err }));
  }, SHARE_RENEW_MS);
  timer.unref?.();
  return () => clearInterval(timer);
};

// Loop, after the flush (writes refreshed), before the batch lock release
export const releaseEndpointShares = async (shares: EndpointShares | undefined): Promise<void> => {
  if (!shares || shares.ids.size === 0) return;
  await redisReleaseEndpointShares(shares.holder, Array.from(shares.ids));
};

export interface MergeMark {
  ids: string[];
  token: string;
}

// mergeEntities, sources locked, before reading their dependencies. Returns the mark (to remove if the
// merge fails before deleting the sources), none on a single writer. Any failure here removes it.
export const markMergeSources = async (context: AuthContext, sourceIds: string[]): Promise<MergeMark | null> => {
  if (!SEQUENCER_CONFIG.multiWriter || sourceIds.length === 0) return null;
  const applying = context.sequencer?.scope === 'applying';
  const own = applying ? getCurrentBatchLock()?.shares?.holder : undefined;
  const mark: MergeMark = { ids: sourceIds, token: randomUUID() };
  try {
    // inside the try: a mark set in part (a command refused, the connection lost) is removed with the rest
    await redisMarkMergeSources(sourceIds, mark.token, MERGE_MARK_TTL_MS);
    const bound = applying ? MERGE_WAIT_APPLYING_MS : MERGE_WAIT_MAX_MS;
    const start = Date.now();
    let holders = await redisEndpointShareHolders(sourceIds, own);
    while (holders.length > 0) {
      if (Date.now() - start > bound) {
        throw LockTimeoutError({ participantIds: sourceIds }, 'Merge sources still shared by relations of another platform');
      }
      await new Promise((resolve) => {
        setTimeout(resolve, MERGE_WAIT_POLL_MS);
      });
      holders = await redisEndpointShareHolders(sourceIds, own);
    }
    return mark;
  } catch (err) {
    await unmarkMergeSources(mark).catch((cause) => logApp.warn('[SEQUENCER] merge marks not removed, they expire', { cause }));
    throw err;
  }
};

export const unmarkMergeSources = async (mark: MergeMark | null): Promise<void> => {
  if (!mark) return;
  await redisUnmarkMergeSources(mark.ids, mark.token);
};

// task 0040 (multi_writer, dedup before lock): the relation-dedup stamps of relations written outside the
// loop's own locked keys, so a platform that searched them before its batch lock searches again. Under an
// applying batch they are stamped by the loop after its flush; otherwise now (the write is refreshed).
// Known gap: these keys are not locked from before the write until the stamp, so a platform taking its
// batch lock between the write and the stamp keeps its stale search (a duplicate relation). Only the
// relation-dedup keys a batch locks are fully covered.
export const stampWrittenRelations = async (context: AuthContext, relations: { type: string; fromId: string; toId: string }[]): Promise<void> => {
  if (!SEQUENCER_CONFIG.multiWriter || relations.length === 0) return;
  const keys = relations.map(({ type, fromId, toId }) => relationDedupLockKey(type, fromId, toId));
  const batchKeys = context.sequencer?.scope === 'applying' ? getCurrentBatchLock()?.writtenDedupKeys : undefined;
  if (batchKeys) {
    keys.forEach((key) => batchKeys.add(key));
    return;
  }
  await bumpLockStamps(keys, DEDUP_STAMP_TTL_S);
};
