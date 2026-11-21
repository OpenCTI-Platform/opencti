import { describe, expect, it } from 'vitest';
import { createDenormBuffer } from '../../../src/database/sequencer/denorm-buffer';
import type { DenormBufferStore, DenormInflight, DenormTarget } from '../../../src/database/sequencer/denorm-buffer';
import { denormTargetBulkLines, toDenormTarget } from '../../../src/database/engine';

// task 0040 append buffer: the "to" side appends of hot documents (a misp external reference collects 26k citing
// ids, each append re-indexes its 1 MB document) wait in Redis and are written once per flush period per document.
// Each test names the lost, doubled or misordered append it guards against.

const OPTIONS = { flushPeriodMs: 1000, targetMaxIds: 5, maxIds: 100, flushBatch: 2 };

const targetOf = (id: string, ids: string[], updatedAt = '2026-11-20T10:00:00.000Z'): DenormTarget => ({
  id,
  index: 'opencti_stix_meta_objects-000001',
  docId: id,
  entityType: 'External-Reference',
  updatedAt,
  groups: [{ relation: 'external-reference', field: 'internal_id', ids }],
});

// In-memory store with the semantics of the Redis one: one set per document and field, a pending time per document,
// takes moved atomically into a flush that stays in flight until done
const memoryStore = () => {
  const buffered = new Map<string, DenormTarget>();
  const pendingSince = new Map<string, number>();
  const flights = new Map<string, { at: number; targets: DenormTarget[] }>();
  let lease: string | null = null;
  const size = () => [...buffered.values()].reduce((n, t) => n + t.groups.reduce((m, g) => m + g.ids.length, 0), 0);
  const store: DenormBufferStore & { buffered: typeof buffered; flights: typeof flights; setLease: (t: string | null) => void } = {
    buffered,
    flights,
    setLease: (t) => {
      lease = t;
    },
    add: async (targets, maxIds, targetMaxIds, nowMs) => {
      if (size() >= maxIds) return false;
      targets.forEach((target) => {
        const current = buffered.get(target.id) ?? { ...target, groups: [] };
        target.groups.forEach((group) => {
          const existing = current.groups.find((g) => g.relation === group.relation && g.field === group.field);
          if (existing) existing.ids = [...new Set([...existing.ids, ...group.ids])];
          else current.groups.push({ ...group, ids: [...new Set(group.ids)] });
        });
        if (current.updatedAt < target.updatedAt) current.updatedAt = target.updatedAt;
        buffered.set(target.id, current);
        const count = current.groups.reduce((n, g) => n + g.ids.length, 0);
        if (count >= targetMaxIds) pendingSince.set(target.id, 1);
        else if (!pendingSince.has(target.id)) pendingSince.set(target.id, nowMs);
      });
      return true;
    },
    due: async (beforeMs, limit) => [...pendingSince.entries()].filter(([, at]) => at <= beforeMs)
      .sort((a, b) => a[1] - b[1]).slice(0, limit).map(([id]) => id),
    pending: async (ids) => ids.filter((id) => pendingSince.has(id)),
    oldestPendingMs: async () => {
      const times = [...pendingSince.values()].filter((at) => at > 1);
      return times.length > 0 ? Math.min(...times) : null;
    },
    take: async (ids, flushId, nowMs) => {
      const taken = ids.flatMap((id) => {
        pendingSince.delete(id);
        const target = buffered.get(id);
        buffered.delete(id);
        return target ? [target] : [];
      });
      if (taken.length > 0) flights.set(flushId, { at: nowMs, targets: taken });
      return taken;
    },
    done: async (flushId) => {
      flights.delete(flushId);
    },
    inflight: async (beforeMs): Promise<DenormInflight[]> => [...flights.entries()]
      .filter(([, f]) => f.at <= beforeMs).map(([flushId, f]) => ({ flushId, targets: f.targets })),
    acquireLease: async (token) => {
      if (lease === null || lease === token) {
        lease = token;
        return true;
      }
      return false;
    },
    releaseLease: async (token) => {
      if (lease === token) lease = null;
    },
  };
  return store;
};

const recordingWriter = (fail = false) => {
  const writes: Array<{ targets: DenormTarget[]; replay: boolean }> = [];
  const write = async (targets: DenormTarget[], replay: boolean) => {
    if (fail) throw new Error('es down');
    writes.push({ targets, replay });
  };
  return { writes, write };
};

const idsOf = (writes: Array<{ targets: DenormTarget[] }>) => writes.flatMap((w) => w.targets.flatMap((t) => t.groups.flatMap((g) => g.ids))).sort();

describe('append buffer: buffering and periodic flush', () => {
  it('should write the appends of several batches to one document in one update, each id once (no rewrite per batch)', async () => {
    const store = memoryStore();
    const { writes, write } = recordingWriter();
    const buffer = createDenormBuffer(store, write, OPTIONS);
    expect(await buffer.add([targetOf('ref-1', ['a', 'b'])])).toBe(true);
    expect(await buffer.add([targetOf('ref-1', ['b', 'c'], '2026-11-20T10:00:05.000Z')])).toBe(true);
    await buffer.flush(['ref-1']);
    expect(writes).toHaveLength(1);
    expect(writes[0].replay).toBe(false);
    expect(idsOf(writes)).toEqual(['a', 'b', 'c']);
    // refreshed_at of the latest commit that buffered an append
    expect(writes[0].targets[0].updatedAt).toBe('2026-11-20T10:00:05.000Z');
    expect(store.flights.size).toBe(0);
  });

  it('should refuse over the global cap so that the caller writes directly (no append dropped)', async () => {
    const store = memoryStore();
    const { write } = recordingWriter();
    const buffer = createDenormBuffer(store, write, { ...OPTIONS, maxIds: 2 });
    expect(await buffer.add([targetOf('ref-1', ['a', 'b'])])).toBe(true);
    expect(await buffer.add([targetOf('ref-2', ['c'])])).toBe(false);
    expect(store.buffered.has('ref-2')).toBe(false);
  });

  it('should flush only the documents waiting longer than the flush period, and only on the lease holder', async () => {
    const store = memoryStore();
    const { writes, write } = recordingWriter();
    const buffer = createDenormBuffer(store, write, OPTIONS);
    const now = Date.now();
    await store.add([targetOf('old', ['a'])], 100, 5, now - 5000);
    await store.add([targetOf('fresh', ['b'])], 100, 5, now);
    store.setLease('another node');
    await buffer.tick();
    expect(writes).toHaveLength(0);
    store.setLease(null);
    await buffer.tick();
    expect(idsOf(writes)).toEqual(['a']);
    expect(store.buffered.has('fresh')).toBe(true);
  });

  it('should flush a document over its per-document cap at the next tick, whatever its age (bounded array growth in Redis)', async () => {
    const store = memoryStore();
    const { writes, write } = recordingWriter();
    const buffer = createDenormBuffer(store, write, OPTIONS);
    await buffer.add([targetOf('hot', ['a', 'b', 'c', 'd', 'e'])]);
    await buffer.tick();
    expect(idsOf(writes)).toEqual(['a', 'b', 'c', 'd', 'e']);
  });

  it('should flush every due document across several flush batches in one tick', async () => {
    const store = memoryStore();
    const { writes, write } = recordingWriter();
    const buffer = createDenormBuffer(store, write, OPTIONS);
    const old = Date.now() - 5000;
    await store.add([targetOf('r1', ['a']), targetOf('r2', ['b']), targetOf('r3', ['c'])], 100, 5, old);
    await buffer.tick();
    expect(idsOf(writes)).toEqual(['a', 'b', 'c']);
    expect(store.buffered.size).toBe(0);
  });
});

describe('append buffer: failures and removals', () => {
  it('should keep a failed flush in flight and replay it, contains-guarded, on the next lease holder (no lost append)', async () => {
    const store = memoryStore();
    const failing = recordingWriter(true);
    const first = createDenormBuffer(store, failing.write, OPTIONS);
    await first.add([targetOf('ref-1', ['a'])]);
    await expect(first.flush(['ref-1'])).rejects.toThrow('es down');
    expect(store.flights.size).toBe(1);
    // the flush is older than the lease TTL when the next holder takes over
    const [flight] = [...store.flights.values()];
    flight.at -= 120000;
    store.setLease(null);
    const { writes, write } = recordingWriter();
    const next = createDenormBuffer(store, write, OPTIONS);
    await next.tick();
    expect(writes).toHaveLength(1);
    expect(writes[0].replay).toBe(true);
    expect(idsOf(writes)).toEqual(['a']);
    expect(store.flights.size).toBe(0);
  });

  it('should not replay a flush still young (its taker may be writing it)', async () => {
    const store = memoryStore();
    await store.add([targetOf('ref-1', ['a'])], 100, 5, Date.now());
    await store.take(['ref-1'], 'live-flush', Date.now());
    const { writes, write } = recordingWriter();
    await createDenormBuffer(store, write, OPTIONS).tick();
    expect(writes).toHaveLength(0);
    expect(store.flights.has('live-flush')).toBe(true);
  });

  it('should flush the pending appends of a document before a removal on it', async () => {
    const store = memoryStore();
    const { writes, write } = recordingWriter();
    const buffer = createDenormBuffer(store, write, OPTIONS);
    await buffer.add([targetOf('ref-1', ['a'])]);
    await buffer.flushFirst(['ref-1', 'ref-2']);
    expect(idsOf(writes)).toEqual(['a']);
    await buffer.flushFirst(['ref-2']);
    expect(writes).toHaveLength(1);
  });

  it('should flush everything pending at a graceful stop when it holds the lease', async () => {
    const store = memoryStore();
    const { writes, write } = recordingWriter();
    const buffer = createDenormBuffer(store, write, OPTIONS);
    await buffer.add([targetOf('fresh', ['a'])]);
    await buffer.stop();
    expect(idsOf(writes)).toEqual(['a']);
  });
});

describe('append buffer: engine side', () => {
  const relation = (fromId: string) => ({ to: { internal_id: fromId } });

  it('should build one target per document with the ids of the other endpoints, grouped by type and field', () => {
    const impacts = [
      { relationshipType: 'external-reference', refField: 'internal_id', type: 'External-Reference', ...relation('obj-1') },
      { relationshipType: 'external-reference', refField: 'internal_id', type: 'External-Reference', ...relation('obj-2') },
    ];
    const target = toDenormTarget('ref-1', { _index: 'meta-1', _id: 'doc-1' }, impacts, '2026-11-20T10:00:00.000Z');
    expect(target).toEqual({
      id: 'ref-1',
      index: 'meta-1',
      docId: 'doc-1',
      entityType: 'External-Reference',
      updatedAt: '2026-11-20T10:00:00.000Z',
      groups: [{ relation: 'external-reference', field: 'internal_id', ids: ['obj-1', 'obj-2'] }],
    });
  });

  it('should write a flush with the same script parameters as the direct append (contains-guarded meta ref, refreshed_at)', () => {
    const [action, update] = denormTargetBulkLines(targetOf('ref-1', ['a', 'b']), false) as any[];
    expect(action.update).toMatchObject({ _index: 'opencti_stix_meta_objects-000001', _id: 'ref-1' });
    // external-reference is a unidirectional meta ref: the direct path already adds its ids if absent
    expect(update.script.params.distinct_refs).toEqual([{ field: 'rel_external-reference.internal_id', ids: ['a', 'b'] }]);
    expect(update.script.params.appended_refs).toEqual([]);
    expect(update.script.params.timestamp_fields).toEqual(['refreshed_at']);
  });

  it('should write a replay contains-guarded even for a type appended with addAll, so that ids already landed are not doubled', () => {
    const container = { ...targetOf('obj-1', ['report-1']), entityType: 'Indicator', groups: [{ relation: 'object', field: 'internal_id', ids: ['report-1'] }] };
    const [, direct] = denormTargetBulkLines(container, false) as any[];
    expect(direct.script.params.appended_refs).toEqual([{ field: 'rel_object.internal_id', ids: ['report-1'] }]);
    const [, replay] = denormTargetBulkLines(container, true) as any[];
    expect(replay.script.params.appended_refs).toEqual([]);
    expect(replay.script.params.distinct_refs).toEqual([{ field: 'rel_object.internal_id', ids: ['report-1'] }]);
  });
});
