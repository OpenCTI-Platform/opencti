// Relationships whose source or target does not exist yet. Today the platform refuses them and the worker sends
// the message again later; here they wait in their own index, invisible to every read, and are written through
// the normal path once their ends exist. One whose end is deleted is refused, as today; one still waiting after
// `ttlMs` is dropped and counted.
import * as R from 'ramda';
import { lockfreeContext } from './context';
import { elRawBulk, elRawSearch, elRefreshIndices } from '../../database/engine';
import { ES_INDEX_PREFIX } from '../../database/utils';
import { now } from '../../utils/format';
import { deterministicId, type Owner } from './identity';
import { liveOwners } from './load';

export const PENDING_INDEX = `lockfree_pending_${ES_INDEX_PREFIX}`;

// A relationship input waiting for its ends: `missing` holds the ids of the ends that do not exist yet
interface PendingItem { input: Record<string, any>; missing: string[]; user_id: string }

// A pending item as stored: `missing` lowercased, with the time it started waiting
interface StoredPending { id: string; input: Record<string, any>; missing: string[]; user_id: string; created_at: string }

type PendingOutcome = 'ready' | 'refused' | 'expired' | 'waiting';

// At most this many pending items are looked at per pass
const LIST_SIZE = 10000;

// A stable id per input, so the same pending relationship sent twice waits once
const pendingId = (input: Record<string, any>) => {
  const sortedEntries = Object.keys(input).sort().map((key) => [key, input[key]]);
  return deterministicId(`pending|${JSON.stringify(sortedEntries)}`);
};

export const addPending = async (items: PendingItem[]) => {
  if (items.length === 0) return;
  const body = items.flatMap((item) => [
    { index: { _index: PENDING_INDEX, _id: pendingId(item.input) } },
    { input: JSON.stringify(item.input), missing: item.missing.map((id) => id.toLowerCase()), user_id: item.user_id, created_at: now() },
  ]);
  const response = await elRawBulk(lockfreeContext, { refresh: false, body });
  if (response.errors) throw new Error('Pending store write failed');
};

// Every pending item, oldest first; none when the index does not exist yet
const listPending = async (): Promise<StoredPending[]> => {
  await elRefreshIndices([PENDING_INDEX]).catch(() => undefined);
  const response = await elRawSearch(lockfreeContext, null as any, null, {
    index: PENDING_INDEX, size: LIST_SIZE, ignore_unavailable: true, body: { sort: [{ created_at: 'asc' }], query: { match_all: {} } },
  }).catch(() => ({ hits: { hits: [] } }));
  return response.hits.hits.map((hit: any) => ({ id: hit._id, ...hit._source, input: JSON.parse(hit._source.input) }));
};

export const countPending = async () => (await listPending()).length;

// Refused when an end is deleted, ready when every end is live, expired when past its time to live
const outcomeOf = (item: StoredPending, owners: Map<string, Owner>, nowMs: number, ttlMs: number): PendingOutcome => {
  const states = item.missing.map((id) => owners.get(id)?.state);
  if (states.some((state) => state === 'deleted')) return 'refused';
  if (states.every((state) => state === 'live')) return 'ready';
  if (nowMs - new Date(item.created_at).getTime() > ttlMs) return 'expired';
  return 'waiting';
};

// Write the pending relationships whose ends now exist (grouped by user), refuse those whose end was deleted,
// drop those past their time to live
export const processPending = async (
  write: (userId: string, inputs: Record<string, any>[]) => Promise<void>,
  opts: { ttlMs: number },
) => {
  const pending = await listPending();
  if (pending.length === 0) return { resolved: 0, refused_deleted: 0, expired: 0, waiting: 0 };
  const { owners } = await liveOwners(R.uniq(pending.flatMap((item) => item.missing)));
  const nowMs = Date.now();
  const byOutcome = R.groupBy((item: StoredPending) => outcomeOf(item, owners, nowMs, opts.ttlMs), pending);
  const ready = byOutcome.ready ?? [];
  const refused = byOutcome.refused ?? [];
  const expired = byOutcome.expired ?? [];
  const readyByUser = R.groupBy((item: StoredPending) => item.user_id, ready);
  for (const [userId, items] of Object.entries(readyByUser)) {
    await write(userId, (items ?? []).map((item) => item.input));
  }
  const done = [...ready, ...refused, ...expired];
  if (done.length > 0) {
    await elRawBulk(lockfreeContext, { refresh: false, body: done.map((item) => ({ delete: { _index: PENDING_INDEX, _id: item.id } })) });
  }
  return { resolved: ready.length, refused_deleted: refused.length, expired: expired.length, waiting: pending.length - done.length };
};
