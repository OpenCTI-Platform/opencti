import { describe, expect, it } from 'vitest';
import { v4 as uuidv4 } from 'uuid';
import { getClientBase, redisDenormBufferStore as store } from '../../../src/database/redis';
import type { DenormTarget } from '../../../src/database/sequencer/denorm-buffer';

// task 0040 append buffer: the Redis store (Lua in the {dn} slot) the buffer relies on. The unit tests run the
// buffer on an in-memory store with the same semantics; this file pins those semantics on Redis itself: one set
// per document and field, the latest commit time, the urgent score over the per-document cap, a total counting the
// ids until done or moved aside (in flight included), atomic takes into a flush that stays in flight with a mark on
// each of its documents, failed writes counted per flush and moved aside at the limit.

const targetOf = (id: string, ids: string[], updatedAt = '2026-11-21T10:00:00.000Z'): DenormTarget => ({
  id,
  index: 'test_stix_meta_objects-000001',
  docId: `doc-${id}`,
  entityType: 'External-Reference',
  updatedAt,
  groups: [{ relation: 'external-reference', field: 'internal_id', ids }],
});
const total = async () => Number(await getClientBase().get('{dn}:total') ?? '0');
const BIG = 1e12;

describe('Append buffer Redis store (task 0040)', () => {
  it('should merge the appends of a document into one set per field, keep the latest commit time, and take them once', async () => {
    const doc = uuidv4();
    const before = await total();
    expect(await store.add([targetOf(doc, ['a', 'b'], '2026-11-21T10:00:05.000Z')], BIG, 1000, 1000)).toBe(true);
    expect(await store.add([targetOf(doc, ['b', 'c'], '2026-11-21T10:00:01.000Z')], BIG, 1000, 2000)).toBe(true);
    expect(await total()).toBe(before + 3);
    expect(await store.pending([doc, uuidv4()])).toEqual([doc]);
    const flushId = uuidv4();
    const [taken] = await store.take([doc], flushId, 3000);
    expect(taken.groups[0].ids.sort()).toEqual(['a', 'b', 'c']);
    expect(taken.updatedAt).toBe('2026-11-21T10:00:05.000Z');
    expect(taken.docId).toBe(`doc-${doc}`);
    // taken: no longer pending, in flight with a mark on the document, still counted
    expect(await store.pending([doc])).toEqual([]);
    expect(await store.inflightOf([doc])).toEqual([flushId]);
    expect((await store.flight(flushId))?.[0].groups[0].ids.sort()).toEqual(['a', 'b', 'c']);
    expect(await total()).toBe(before + 3);
    expect(await store.take([doc], uuidv4(), 3000)).toEqual([]);
    await store.done(flushId);
    expect(await store.flight(flushId)).toBeNull();
    expect(await store.inflightOf([doc])).toEqual([]);
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
    const flushId = uuidv4();
    await store.take([old, recent, hot], flushId, 7000);
    await store.done(flushId);
  });

  it('should refuse an add once the total reaches the cap, in-flight ids included', async () => {
    const doc = uuidv4();
    await store.add([targetOf(doc, ['a', 'b'])], BIG, 1000, 1000);
    const flushId = uuidv4();
    await store.take([doc], flushId, 2000);
    const cap = await total();
    expect(await store.add([targetOf(uuidv4(), ['c'])], cap, 1000, 3000)).toBe(false);
    await store.done(flushId);
    expect(await store.add([targetOf(uuidv4(), ['c'])], cap, 1000, 3000)).toBe(true);
  });

  it('should list the in-flight flushes oldest first and move a flush aside at its attempt limit, keeping its content', async () => {
    const [d1, d2] = [uuidv4(), uuidv4()];
    await store.add([targetOf(d1, ['x']), targetOf(d2, ['y'])], BIG, 1000, 1000);
    const [f1, f2] = [uuidv4(), uuidv4()];
    await store.take([d1], f1, 1);
    await store.take([d2], f2, 2);
    const flights = await store.inflight(1000);
    const mine = flights.filter((f) => [f1, f2].includes(f.flushId));
    expect(mine).toEqual([{ flushId: f1, docIds: [d1] }, { flushId: f2, docIds: [d2] }]);
    const before = await total();
    expect(await store.failed(f1, 2, 5000)).toBe(false);
    expect(await store.flight(f1)).not.toBeNull();
    expect(await store.failed(f1, 2, 5000)).toBe(true);
    expect(await store.flight(f1)).toBeNull();
    expect(await store.inflightOf([d1])).toEqual([]);
    expect(await total()).toBe(before - 1);
    expect(Number(await getClientBase().zscore('{dn}:dead', f1))).toBe(5000);
    expect(await getClientBase().smembers(`{dn}:fladd:${f1}:${d1}:external-reference|internal_id`)).toEqual(['x']);
    await store.done(f2);
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
