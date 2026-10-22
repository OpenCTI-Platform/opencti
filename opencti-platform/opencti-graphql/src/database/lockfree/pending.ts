// Relationships whose source or target does not exist yet. Today the platform refuses them and the worker sends
// the message again later; here they wait in their own index, invisible to every read, and are written through
// the normal path once their ends exist. One whose end is deleted is refused, as today; one still waiting after
// `ttlMs` is dropped and counted.
import * as R from 'ramda';
import { lockfreeContext } from './context';
import { elRawBulk, elRawSearch, elRefreshIndices } from '../../database/engine';
import { ES_INDEX_PREFIX } from '../../database/utils';
import { now } from '../../utils/format';
import { deterministicId } from './identity';
import { liveOwners } from './load';

export const PENDING_INDEX = `lockfree_pending_${ES_INDEX_PREFIX}`;

export interface PendingItem { input: Record<string, any>; missing: string[]; user_id: string }

// A stable id per input, so the same pending relationship sent twice waits once
const pendingId = (input: Record<string, any>) => deterministicId(`pending|${JSON.stringify(Object.keys(input).sort().map((k) => [k, input[k]]))}`);

export const addPending = async (items: PendingItem[]) => {
  if (items.length === 0) return;
  const body = items.flatMap((item) => [
    { index: { _index: PENDING_INDEX, _id: pendingId(item.input) } },
    { input: JSON.stringify(item.input), missing: item.missing.map((m) => m.toLowerCase()), user_id: item.user_id, created_at: now() },
  ]);
  const response: any = await elRawBulk(lockfreeContext, { refresh: false, body });
  if (response.errors) throw new Error('Pending store write failed');
};

const listPending = async () => {
  await elRefreshIndices([PENDING_INDEX]).catch(() => undefined);
  const response: any = await elRawSearch(lockfreeContext, null as any, null, {
    index: PENDING_INDEX, size: 10000, ignore_unavailable: true, body: { sort: [{ created_at: 'asc' }], query: { match_all: {} } },
  }).catch(() => ({ hits: { hits: [] } }));
  return response.hits.hits.map((h: any) => ({ id: h._id, ...h._source, input: JSON.parse(h._source.input) }));
};

export const countPending = async () => (await listPending()).length;

// Write the pending relationships whose ends now exist (grouped by user), refuse those whose end was deleted,
// drop those past their time to live
export const processPending = async (
  write: (userId: string, inputs: Record<string, any>[]) => Promise<void>,
  opts: { ttlMs: number },
) => {
  const pending = await listPending();
  if (pending.length === 0) return { resolved: 0, refused_deleted: 0, expired: 0, waiting: 0 };
  const { owners } = await liveOwners(R.uniq(pending.flatMap((p: any) => p.missing)));
  const ready: any[] = [];
  const refused: any[] = [];
  const expired: any[] = [];
  const nowMs = Date.now();
  pending.forEach((p: any) => {
    const states = p.missing.map((m: string) => owners.get(m)?.state);
    if (states.some((s: string) => s === 'deleted')) refused.push(p);
    else if (states.every((s: string) => s === 'live')) ready.push(p);
    else if (nowMs - new Date(p.created_at).getTime() > opts.ttlMs) expired.push(p);
  });
  const byUser = R.groupBy((p: any) => p.user_id, ready);
  for (const [userId, items] of Object.entries(byUser)) {
    await write(userId, (items ?? []).map((p: any) => p.input));
  }
  const done = [...ready, ...refused, ...expired];
  if (done.length > 0) {
    await elRawBulk(lockfreeContext, { refresh: false, body: done.map((p: any) => ({ delete: { _index: PENDING_INDEX, _id: p.id } })) });
  }
  return { resolved: ready.length, refused_deleted: refused.length, expired: expired.length, waiting: pending.length - done.length };
};

export const clearPending = async () => {
  await elRawBulk(lockfreeContext, { refresh: true, body: [{ delete: { _index: PENDING_INDEX, _id: 'none' } }] }).catch(() => undefined);
  const { elRawDeleteByQuery } = await import('../../../src/database/engine');
  await elRawDeleteByQuery({ index: PENDING_INDEX, refresh: true, ignore_unavailable: true, body: { query: { match_all: {} } } }).catch(() => undefined);
};
