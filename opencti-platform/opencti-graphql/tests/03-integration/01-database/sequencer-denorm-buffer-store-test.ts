import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { v4 as uuidv4 } from 'uuid';
import { getClientBase, redisDenormBufferStore as store } from '../../../src/database/redis';
import type { DenormEdit, DenormTarget } from '../../../src/database/sequencer/denorm-buffer';

// task 0040 append buffer: the Redis store (Lua in the {dn} slot) the buffer relies on. The unit tests run the
// buffer on an in-memory store with the same semantics; this file pins those semantics on Redis itself: one set
// per document and field, the latest commit time, the urgent score over the per-document cap, a total counting the
// ids until done or moved aside (in flight included), atomic takes into a flush that stays in flight with a mark on
// each of its documents (documents emptied by removals dropped), removals and renames applied to pending, in-flight
// and moved aside appends, a tombstone on each flush an edit hit (kept a while after done, cancelled by an add of
// the same id), failed writes counted per flush, replayed after a back-off, moved aside at the limit and age,
// requeued at start.

const targetOf = (id: string, ids: string[], updatedAt = '2026-11-21T10:00:00.000Z'): DenormTarget => ({
  id,
  index: 'test_stix_meta_objects-000001',
  docId: `doc-${id}`,
  entityType: 'External-Reference',
  updatedAt,
  groups: [{ relation: 'external-reference', field: 'internal_id', ids }],
});
const removal = (docId: string, from: string): DenormEdit => ({ docId, relation: 'external-reference', field: 'internal_id', from, to: null });
const total = async () => Number(await getClientBase().get('{dn}:total') ?? '0');
const marksOf = async (doc: string) => (await getClientBase().smembers(`{dn}:infl:${doc}`)).sort();
const tombsOf = async (flushId: string, doc: string) => ((await store.tombstones(flushId, [doc]))[0]?.edits ?? []).map((e) => e.from).sort();
const BIG = 1e12;
const NOW = 1e12; // far above any take time of these tests: every flush is replayable
const RETRY = { baseMs: 1000, maxMs: 5000 };

describe('Append buffer Redis store (task 0040)', () => {
  const opened: string[] = [];
  const take = async (ids: string[], nowMs = 3000) => {
    const flushId = uuidv4();
    opened.push(flushId);
    return { flushId, taken: await store.take(ids, flushId, nowMs) };
  };
  // the totals below are exact: flushes left by earlier runs (moved aside or in flight) are dropped first
  beforeAll(async () => {
    await store.requeueDead(0);
    const left = await store.inflight(100000, Number.MAX_SAFE_INTEGER);
    for (let i = 0; i < left.length; i += 1) await store.done(left[i].flushId);
  });
  afterAll(async () => {
    for (let i = 0; i < opened.length; i += 1) await store.done(opened[i]);
  });

  it('should merge the appends of a document into one set per field, keep the latest commit time, and take them once', async () => {
    const doc = uuidv4();
    const before = await total();
    expect(await store.add([targetOf(doc, ['a', 'b'], '2026-11-21T10:00:05.000Z')], BIG, 1000, 1000)).toBe(true);
    expect(await store.add([targetOf(doc, ['b', 'c'], '2026-11-21T10:00:01.000Z')], BIG, 1000, 2000)).toBe(true);
    expect(await total()).toBe(before + 3);
    expect(await store.pending([doc, uuidv4()])).toEqual([doc]);
    const { flushId, taken: [taken] } = await take([doc]);
    expect(taken.groups[0].ids.sort()).toEqual(['a', 'b', 'c']);
    expect(taken.updatedAt).toBe('2026-11-21T10:00:05.000Z');
    expect(taken.docId).toBe(`doc-${doc}`);
    // taken: no longer pending, in flight with a mark on the document, still counted
    expect(await store.pending([doc])).toEqual([]);
    expect(await marksOf(doc)).toEqual([flushId]);
    expect((await store.flight(flushId))?.[0].groups[0].ids.sort()).toEqual(['a', 'b', 'c']);
    expect(await total()).toBe(before + 3);
    expect((await take([doc])).taken).toEqual([]);
    await store.done(flushId);
    expect(await store.flight(flushId)).toBeNull();
    expect(await marksOf(doc)).toEqual([]);
    expect(await total()).toBe(before);
  });

  it('should give the due documents oldest first, a document over its cap first of all', async () => {
    const [old, recent, hot] = [uuidv4(), uuidv4(), uuidv4()];
    await store.add([targetOf(recent, ['r'])], BIG, 1000, 5000);
    await store.add([targetOf(old, ['o'])], BIG, 1000, 4000);
    await store.add([targetOf(hot, ['h1', 'h2', 'h3'])], BIG, 3, 6000);
    const due = await store.due(5000, 1000);
    const mine = due.filter((id) => [old, recent, hot].includes(id));
    expect(mine).toEqual([hot, old, recent]);
    expect(await store.due(4500, 1000)).not.toContain(recent);
    await store.done((await take([old, recent, hot], 7000)).flushId);
  });

  it('should refuse an add once the total reaches the cap, in-flight ids included', async () => {
    const doc = uuidv4();
    await store.add([targetOf(doc, ['a', 'b'])], BIG, 1000, 1000);
    const { flushId } = await take([doc], 2000);
    const cap = await total();
    const other = uuidv4();
    expect(await store.add([targetOf(other, ['c'])], cap, 1000, 3000)).toBe(false);
    await store.done(flushId);
    expect(await store.add([targetOf(other, ['c'])], cap, 1000, 3000)).toBe(true);
    await store.done((await take([other])).flushId);
  });

  it('should refuse an incomplete target whole, so that a script error cannot leave half a batch in Redis', async () => {
    const [doc, broken] = [uuidv4(), uuidv4()];
    const before = await total();
    await expect(store.add([targetOf(doc, ['a']), { ...targetOf(broken, ['b']), index: '' }], BIG, 1000, 1000)).rejects.toThrow();
    expect(await store.pending([doc, broken])).toEqual([]);
    expect(await total()).toBe(before);
  });

  it('should list the replayable in-flight flushes oldest first, back off a failed one, move it aside only once failing long enough, and requeue it', async () => {
    const [d1, d2] = [uuidv4(), uuidv4()];
    await store.add([targetOf(d1, ['x']), targetOf(d2, ['y'])], BIG, 1000, 1000);
    const { flushId: f1 } = await take([d1], 1);
    const { flushId: f2 } = await take([d2], 2);
    const mineOf = async (nowMs: number) => (await store.inflight(100000, nowMs)).filter((f) => [f1, f2].includes(f.flushId));
    expect(await mineOf(NOW)).toEqual([{ flushId: f1, docIds: [d1] }, { flushId: f2, docIds: [d2] }]);
    const before = await total();
    expect(await store.failed(f1, 2, 1000, 5000, RETRY)).toBe(false);
    expect((await mineOf(5999)).map((f) => f.flushId), 'backing off until 5000 + 1000').toEqual([f2]);
    expect((await mineOf(6000)).map((f) => f.flushId)).toEqual([f2, f1]);
    expect(await store.failed(f1, 2, 1000, 5500, RETRY), 'enough attempts, not long enough').toBe(false);
    expect((await mineOf(7499)).map((f) => f.flushId), 'back-off doubled: 5500 + 2000').toEqual([f2]);
    expect(await store.flight(f1)).not.toBeNull();
    expect(await store.failed(f1, 2, 1000, 6000, RETRY)).toBe(true);
    expect(await store.flight(f1)).toBeNull();
    expect((await mineOf(NOW)).map((f) => f.flushId)).toEqual([f2]);
    expect(await marksOf(d1), 'a flush moved aside keeps its marks').toEqual([f1]);
    expect(await total()).toBe(before - 1);
    expect(Number(await getClientBase().zscore('{dn}:dead', f1))).toBe(6000);
    expect(await getClientBase().smembers(`{dn}:fladd:${f1}:${d1}:external-reference|internal_id`)).toEqual(['x']);
    expect(await store.deadCount()).toBeGreaterThanOrEqual(1);
    expect(await store.requeueDead(7000)).toBeGreaterThanOrEqual(1);
    expect(await getClientBase().zscore('{dn}:dead', f1)).toBeNull();
    expect((await store.flight(f1))?.[0].groups[0].ids).toEqual(['x']);
    expect(await total()).toBe(before);
    // the attempts start again from zero
    expect(await store.failed(f1, 2, 0, 8000, RETRY)).toBe(false);
    await store.done(f1);
    await store.done(f2);
    expect(await marksOf(d1)).toEqual([]);
  });

  it('should drop a removed id and rename a merged one in the pending appends, the total following, and return what it removed', async () => {
    const doc = uuidv4();
    await store.add([targetOf(doc, ['a', 'b', 'source'])], BIG, 1000, 1000);
    const before = await total();
    const removed = await store.edit([removal(doc, 'a'), { ...removal(doc, 'source'), to: 'target' }, removal(doc, 'absent')]);
    expect(removed).toEqual([{ ...targetOf(doc, ['a', 'source']), updatedAt: removed[0].updatedAt }]);
    expect(await total()).toBe(before - 1);
    // rename onto an id already there: one id less
    await store.edit([{ ...removal(doc, 'b'), to: 'target' }]);
    expect(await total()).toBe(before - 2);
    const { taken: [taken] } = await take([doc]);
    expect(taken.groups[0].ids).toEqual(['target']);
  });

  it('should drop at the take a document whose appends were all removed', async () => {
    const doc = uuidv4();
    await store.add([targetOf(doc, ['a'])], BIG, 1000, 1000);
    await store.edit([removal(doc, 'a')]);
    const { flushId, taken } = await take([doc]);
    expect(taken).toEqual([]);
    expect(await store.flight(flushId)).toBeNull();
    expect(await getClientBase().exists(`{dn}:meta:${doc}`, `{dn}:groups:${doc}`)).toBe(0);
  });

  it('should tombstone only the flushes an edit hit, and keep their tombstones after done for a late writer', async () => {
    const doc = uuidv4();
    await store.add([targetOf(doc, ['a', 'b'])], BIG, 1000, 1000);
    const { flushId: f1 } = await take([doc]);
    await store.add([targetOf(doc, ['c'])], BIG, 1000, 1000);
    const { flushId: f2 } = await take([doc]);
    await store.add([targetOf(doc, ['d'])], BIG, 1000, 1000);
    const before = await total();
    await store.edit([removal(doc, 'a'), removal(doc, 'c'), removal(doc, 'd'), removal(doc, 'never-buffered')]);
    expect(await total()).toBe(before - 3);
    expect((await store.flight(f1))?.[0].groups[0].ids).toEqual(['b']);
    expect(await tombsOf(f1, doc)).toEqual(['a']);
    expect(await tombsOf(f2, doc)).toEqual(['c']);
    await store.done(f1);
    expect(await tombsOf(f1, doc), 'kept after done, for a writer whose lock expired').toEqual(['a']);
    const ttl = await getClientBase().ttl(`{dn}:tomb:${f1}:${doc}`);
    expect(ttl).toBeGreaterThan(0);
    expect(ttl).toBeLessThanOrEqual(600);
    await store.done(f2);
  });

  it('should cancel the tombstones of an id added again in every flush of its document', async () => {
    const doc = uuidv4();
    await store.add([targetOf(doc, ['a', 'b'])], BIG, 1000, 1000);
    const { flushId } = await take([doc]);
    await store.edit([removal(doc, 'a'), removal(doc, 'b')]);
    await store.add([targetOf(doc, ['a'])], BIG, 1000, 2000);
    expect(await tombsOf(flushId, doc)).toEqual(['b']);
    await store.done(flushId);
    await store.done((await take([doc])).flushId);
  });

  it('should edit a flush moved aside out of the total and tombstone it, so that its replay erases what its failed writes landed', async () => {
    const doc = uuidv4();
    await store.add([targetOf(doc, ['a', 'b'])], BIG, 1000, 1000);
    const { flushId } = await take([doc]);
    expect(await store.failed(flushId, 1, 0, 2000, RETRY)).toBe(true);
    const before = await total();
    await store.edit([removal(doc, 'a')]);
    expect(await total()).toBe(before);
    expect(await tombsOf(flushId, doc)).toEqual(['a']);
    await store.requeueDead(3000);
    expect((await store.flight(flushId))?.[0].groups[0].ids).toEqual(['b']);
    expect(await total()).toBe(before + 1);
    await store.done(flushId);
    expect(await total()).toBe(before);
  });

  it('should hold the lease for one token at a time', async () => {
    const [a, b] = [uuidv4(), uuidv4()];
    await getClientBase().del('{dn}:lease');
    expect(await store.acquireLease(a, 5000)).toBe(true);
    expect(await store.acquireLease(b, 5000)).toBe(false);
    expect(await store.acquireLease(a, 5000)).toBe(true);
    await store.releaseLease(a);
    expect(await store.acquireLease(b, 5000)).toBe(true);
    await store.releaseLease(b);
  });
});
