// POC ingestion sequencer (task 0040 defect 1, multi_writer): relations against a concurrent merge of
// their endpoints. Under multi_writer a batch does not lock its relations' endpoints across platforms
// (computeOwnLockKeys: they only receive commuting ref appends), so a merge on another platform could read
// the source's dependencies before the relation was written, then delete the source: the relation was
// lost with it or left on the deleted source (0-6 per mix285k run). Shared / exclusive on the endpoints:
// a batch SHARES the endpoints of the relations it writes until its flush is refreshed (relations never
// exclude each other, hot endpoints stay free); a merge MARKS its sources before reading their
// dependencies and waits for the other holders. A share on a marked entity is refused with a LOCK_ERROR:
// the group starts a new cycle and resolves to the merge target. The mark outlives the merge (10 min) so
// a platform still resolving the source from its identity map is refused too.
import { randomUUID } from 'node:crypto';
import conf, { logApp } from '../../config/conf';
import { LockTimeoutError } from '../../config/errors';
import { redisEndpointShareHolders, redisMarkMergeSources, redisReleaseEndpointShares, redisShareEndpoints, redisUnmarkMergeSources } from '../redis';
import type { AuthContext } from '../../types/user';
import { getCurrentBatchLock, type SequencerBatchLock } from './sequencer-batch-lock';
import { SEQUENCER_CONFIG } from './sequencer-config';

// a share outlives a dead holder by the batch lock's own bound
const SHARE_TTL_MS = Number(conf.get('app:concurrency:max_ttl') ?? 60000);
const MERGE_MARK_TTL_MS = 10 * 60 * 1000;
const MERGE_WAIT_MAX_MS = 30000;
const MERGE_WAIT_POLL_MS = 25;

export const newEndpointShares = (): NonNullable<SequencerBatchLock['shares']> => ({ holder: randomUUID(), ids: new Set() });

// The ids of a LOCK_ERROR refused because another platform merges (or merged) them away
export const mergedSourceKeys = (error: any): string[] => {
  const keys = error?.extensions?.data?.mergedSources ?? error?.data?.mergedSources;
  return Array.isArray(keys) ? keys.filter((key: unknown): key is string => typeof key === 'string' && key.length > 0) : [];
};

// Share ids for the current batch: those already shared are skipped, the refused ones are returned
const share = async (shares: NonNullable<SequencerBatchLock['shares']>, ids: string[]): Promise<string[]> => {
  const missing = [...new Set(ids.filter((id) => typeof id === 'string' && id.length > 0 && !shares.ids.has(id)))];
  if (missing.length === 0) return [];
  const refused = await redisShareEndpoints(shares.holder, missing, SHARE_TTL_MS);
  const refusedSet = new Set(refused);
  missing.filter((id) => !refusedSet.has(id)).forEach((id) => shares.ids.add(id));
  return refused;
};

// Loop, after the batch lock: the endpoints the plan resolved, in one round trip. A refused one is left
// to the apply-time share, which fails the relation's group.
export const preShareEndpoints = async (shares: NonNullable<SequencerBatchLock['shares']>, ids: string[]): Promise<void> => {
  await share(shares, ids);
};

// createRelationRaw, before its lock site: the relation's resolved endpoints, under an applying batch
export const shareRelationEndpoints = async (context: AuthContext, ids: string[]): Promise<void> => {
  if (!SEQUENCER_CONFIG.multiWriter || context.sequencer?.scope !== 'applying') return;
  const shares = getCurrentBatchLock()?.shares;
  if (!shares) return;
  const refused = await share(shares, ids);
  if (refused.length > 0) throw LockTimeoutError({ participantIds: refused, mergedSources: refused }, 'Relation endpoint merged by another platform');
};

// Loop, after the flush (writes refreshed), before the batch lock release
export const releaseEndpointShares = async (shares: SequencerBatchLock['shares']): Promise<void> => {
  if (!shares || shares.ids.size === 0) return;
  await redisReleaseEndpointShares(shares.holder, Array.from(shares.ids));
};

// mergeEntities, sources locked, before reading their dependencies. Returns the marked ids (to unmark if
// the merge fails before deleting them), none on a single writer.
export const markMergeSources = async (context: AuthContext, sourceIds: string[]): Promise<string[]> => {
  if (!SEQUENCER_CONFIG.multiWriter || sourceIds.length === 0) return [];
  const own = context.sequencer?.scope === 'applying' ? getCurrentBatchLock()?.shares?.holder : undefined;
  await redisMarkMergeSources(sourceIds, own ?? 'merge', MERGE_MARK_TTL_MS);
  const start = Date.now();
  let holders = await redisEndpointShareHolders(sourceIds, own);
  while (holders.length > 0) {
    if (Date.now() - start > MERGE_WAIT_MAX_MS) {
      await redisUnmarkMergeSources(sourceIds).catch((err) => logApp.error('[SEQUENCER] merge marks not removed', { cause: err }));
      throw LockTimeoutError({ participantIds: sourceIds }, 'Merge sources still shared by relations of another platform');
    }
    await new Promise((resolve) => {
      setTimeout(resolve, MERGE_WAIT_POLL_MS);
    });
    holders = await redisEndpointShareHolders(sourceIds, own);
  }
  return sourceIds;
};

export const unmarkMergeSources = async (sourceIds: string[]): Promise<void> => {
  if (sourceIds.length === 0) return;
  await redisUnmarkMergeSources(sourceIds);
};
