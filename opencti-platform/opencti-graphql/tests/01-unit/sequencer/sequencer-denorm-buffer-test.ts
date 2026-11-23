import { afterEach, describe, expect, it, vi } from 'vitest';
import { createDenormBuffer } from '../../../src/database/sequencer/denorm-buffer';
import type { DenormBufferStore, DenormFlight, DenormLocker, DenormTarget } from '../../../src/database/sequencer/denorm-buffer';
import { bufferableRelations, denormTargetBulkLines, toDenormTarget } from '../../../src/database/engine';

// task 0040 append buffer: the "to" side appends of hot documents (a misp external reference collects 26k citing
// ids, each append re-indexes its 1 MB document) wait in Redis and are written once per flush period per document.
// Each test names the lost, doubled or misordered append it guards against.

const OPTIONS = { flushPeriodMs: 1000, targetMaxIds: 5, maxIds: 100, flushBatch: 2, maxAttempts: 3 };

const targetOf = (id: string, ids: string[], updatedAt = '2026-11-20T10:00:00.000Z'): DenormTarget => ({
  id,
  index: 'opencti_stix_meta_objects-000001',
  docId: id,
  entityType: 'External-Reference',
  updatedAt,
  groups: [{ relation: 'external-reference', field: 'internal_id', ids }],
});

const countOf = (targets: DenormTarget[]) => targets.reduce((n, t) => n + t.groups.reduce((m, g) => m + g.ids.length, 0), 0);

// In-memory store with the semantics of the Redis one (redis.ts redisDenormBufferStore): one set per document and
// field, a pending time per document, a total counting the ids until done or moved aside (in flight included),
// takes moved atomically into a flush that stays in flight until done, failed writes counted per flush
const memoryStore = () => {
  const buffered = new Map<string, DenormTarget>();
  const pendingSince = new Map<string, number>();
  const flights = new Map<string, { at: number; targets: DenormTarget[]; attempts: number }>();
  const dead = new Map<string, DenormTarget[]>();
  const marks = new Map<string, Set<string>>();
  let total = 0;
  let lease: string | null = null;
  const release = (flushId: string) => {
    const flight = flights.get(flushId);
    if (!flight) return;
    total -= countOf(flight.targets);
    flight.targets.forEach((t) => marks.get(t.id)?.delete(flushId));
    flights.delete(flushId);
  };
  const store: DenormBufferStore & {
    buffered: typeof buffered; flights: typeof flights; dead: typeof dead; total: () => number; setLease: (t: string | null) => void;
  } = {
    buffered,
    flights,
    dead,
    total: () => total,
    setLease: (t) => {
      lease = t;
    },
    add: async (targets, maxIds, targetMaxIds, nowMs) => {
      if (total >= maxIds) return false;
      targets.forEach((target) => {
        const current = buffered.get(target.id) ?? { ...target, groups: [] };
        target.groups.forEach((group) => {
          const existing = current.groups.find((g) => g.relation === group.relation && g.field === group.field);
          const before = existing ? existing.ids.length : 0;
          const ids = [...new Set([...(existing?.ids ?? []), ...group.ids])];
          total += ids.length - before;
          if (existing) existing.ids = ids;
          else current.groups.push({ ...group, ids });
        });
        if (current.updatedAt < target.updatedAt) current.updatedAt = target.updatedAt;
        buffered.set(target.id, current);
        if (countOf([current]) >= targetMaxIds) pendingSince.set(target.id, 1);
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
        if (!target) return [];
        const docMarks = marks.get(id) ?? new Set<string>();
        docMarks.add(flushId);
        marks.set(id, docMarks);
        return [target];
      });
      if (taken.length > 0) flights.set(flushId, { at: nowMs, targets: taken, attempts: 0 });
      return taken;
    },
    done: async (flushId) => release(flushId),
    inflight: async (limit): Promise<DenormFlight[]> => [...flights.entries()].sort((a, b) => a[1].at - b[1].at).slice(0, limit)
      .map(([flushId, f]) => ({ flushId, docIds: f.targets.map((t) => t.id) })),
    flight: async (flushId) => flights.get(flushId)?.targets ?? null,
    inflightOf: async (ids) => [...new Set(ids.flatMap((id) => [...(marks.get(id) ?? [])]))],
    failed: async (flushId, maxAttempts) => {
      const flight = flights.get(flushId);
      if (!flight) return false;
      flight.attempts += 1;
      if (flight.attempts < maxAttempts) return false;
      dead.set(flushId, flight.targets);
      release(flushId);
      return true;
    },
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

// Document locks as the engine's locker (one key per document, all or nothing): wait polls until free
const memoryLocker = () => {
  const held = new Set<string>();
  const tryLock = (ids: string[]) => {
    if (ids.some((id) => held.has(id))) return null;
    ids.forEach((id) => held.add(id));
    return { unlock: async () => ids.forEach((id) => held.delete(id)) };
  };
  const locker: DenormLocker = async (ids, wait) => {
    let lock = tryLock(ids);
    while (!lock && wait) {
      await new Promise((resolve) => {
        setTimeout(resolve, 1);
      });
      lock = tryLock(ids);
    }
    return lock;
  };
  return { locker, held, hold: (ids: string[]) => tryLock(ids) };
};

const recordingWriter = (failures = 0) => {
  const writes: Array<{ targets: DenormTarget[]; replay: boolean }> = [];
  let left = failures;
  const write = async (targets: DenormTarget[], replay: boolean) => {
    if (left > 0) {
      left -= 1;
      throw new Error('es down');
    }
    writes.push({ targets, replay });
  };
  return { writes, write };
};

const idsOf = (writes: Array<{ targets: DenormTarget[] }>) => writes.flatMap((w) => w.targets.flatMap((t) => t.groups.flatMap((g) => g.ids))).sort();

afterEach(() => {
  vi.useRealTimers();
});

describe('append buffer: buffering and periodic flush', () => {
  it('should write the appends of several batches to one document in one update, each id once (no rewrite per batch)', async () => {
    const store = memoryStore();
    const { writes, write } = recordingWriter();
    const buffer = createDenormBuffer(store, write, memoryLocker().locker, OPTIONS);
    expect(await buffer.add([targetOf('ref-1', ['a', 'b'])])).toBe(true);
    expect(await buffer.add([targetOf('ref-1', ['b', 'c'], '2026-11-20T10:00:05.000Z')])).toBe(true);
    await buffer.flush(['ref-1']);
    expect(writes).toHaveLength(1);
    expect(writes[0].replay).toBe(false);
    expect(idsOf(writes)).toEqual(['a', 'b', 'c']);
    expect(writes[0].targets[0].updatedAt).toBe('2026-11-20T10:00:05.000Z');
    expect(store.flights.size).toBe(0);
    expect(store.total()).toBe(0);
  });

  it('should refuse over the global cap, in-flight ids included, so that the caller writes directly (no append dropped)', async () => {
    const store = memoryStore();
    const { write } = recordingWriter(1);
    const buffer = createDenormBuffer(store, write, memoryLocker().locker, { ...OPTIONS, maxIds: 2 });
    expect(await buffer.add([targetOf('ref-1', ['a', 'b'])])).toBe(true);
    // the write fails: the two ids stay in flight and still count
    await expect(buffer.flush(['ref-1'])).rejects.toThrow('es down');
    expect(await buffer.add([targetOf('ref-2', ['c'])])).toBe(false);
    expect(store.buffered.has('ref-2')).toBe(false);
  });

  it('should flush only the documents waiting longer than the flush period, and only on the lease holder', async () => {
    const store = memoryStore();
    const { writes, write } = recordingWriter();
    const buffer = createDenormBuffer(store, write, memoryLocker().locker, OPTIONS);
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
    const buffer = createDenormBuffer(store, write, memoryLocker().locker, OPTIONS);
    await buffer.add([targetOf('hot', ['a', 'b', 'c', 'd', 'e'])]);
    await buffer.tick();
    expect(idsOf(writes)).toEqual(['a', 'b', 'c', 'd', 'e']);
  });

  it('should flush every due document across several flush batches in one tick', async () => {
    const store = memoryStore();
    const { writes, write } = recordingWriter();
    const buffer = createDenormBuffer(store, write, memoryLocker().locker, OPTIONS);
    await store.add([targetOf('r1', ['a']), targetOf('r2', ['b']), targetOf('r3', ['c'])], 100, 5, Date.now() - 5000);
    await buffer.tick();
    expect(idsOf(writes)).toEqual(['a', 'b', 'c']);
    expect(store.buffered.size).toBe(0);
  });

  it('should stop flushing between batches once the lease is lost (one flusher at a time)', async () => {
    const store = memoryStore();
    const { writes, write } = recordingWriter();
    const buffer = createDenormBuffer(store, write, memoryLocker().locker, OPTIONS);
    await store.add([targetOf('r1', ['a']), targetOf('r2', ['b']), targetOf('r3', ['c'])], 100, 5, Date.now() - 5000);
    const acquire = store.acquireLease;
    let calls = 0;
    // the tick takes the lease, the renewal after the first batch fails: another node took it
    store.acquireLease = async (token, ttlMs) => {
      calls += 1;
      return calls === 1 ? acquire(token, ttlMs) : false;
    };
    await buffer.tick();
    expect(idsOf(writes)).toEqual(['a', 'b']);
    expect(store.buffered.has('r3')).toBe(true);
  });

  it('should leave the appends pending, not in flight, when their documents cannot be locked', async () => {
    const store = memoryStore();
    const { writes, write } = recordingWriter();
    const locks = memoryLocker();
    const refusing: DenormLocker = async (ids) => locks.locker(ids, false);
    const buffer = createDenormBuffer(store, write, refusing, OPTIONS);
    await buffer.add([targetOf('ref-1', ['a'])]);
    locks.hold(['ref-1']);
    expect(await buffer.flush(['ref-1'])).toBe(0);
    expect(writes).toHaveLength(0);
    expect(store.flights.size).toBe(0);
    expect(await store.pending(['ref-1'])).toEqual(['ref-1']);
  });
});

describe('append buffer: failures and removals', () => {
  it('should replay its own failed flush at its next tick while it keeps the lease (no lost append on one node)', async () => {
    const store = memoryStore();
    const { writes, write } = recordingWriter(1);
    const buffer = createDenormBuffer(store, write, memoryLocker().locker, OPTIONS);
    await store.add([targetOf('ref-1', ['a'])], 100, 5, Date.now() - 5000);
    await buffer.tick();
    expect(store.flights.size).toBe(1);
    await buffer.tick();
    expect(writes).toHaveLength(1);
    expect(writes[0].replay).toBe(true);
    expect(idsOf(writes)).toEqual(['a']);
    expect(store.flights.size).toBe(0);
    expect(store.total()).toBe(0);
  });

  it('should replay a flush left by another node once its documents are free', async () => {
    const store = memoryStore();
    await store.add([targetOf('ref-1', ['a'])], 100, 5, Date.now());
    await store.take(['ref-1'], 'dead-node-flush', Date.now());
    const { writes, write } = recordingWriter();
    await createDenormBuffer(store, write, memoryLocker().locker, OPTIONS).tick();
    expect(writes).toEqual([{ targets: [targetOf('ref-1', ['a'])], replay: true }]);
    expect(store.flights.size).toBe(0);
  });

  it('should not replay a flush whose documents are locked (its writer is still writing it)', async () => {
    const store = memoryStore();
    await store.add([targetOf('ref-1', ['a'])], 100, 5, Date.now());
    await store.take(['ref-1'], 'live-flush', Date.now());
    const locks = memoryLocker();
    locks.hold(['ref-1']);
    const { writes, write } = recordingWriter();
    await createDenormBuffer(store, write, locks.locker, OPTIONS).tick();
    expect(writes).toHaveLength(0);
    expect(store.flights.has('live-flush')).toBe(true);
  });

  it('should move a flush failing every time aside and keep flushing the due documents (no blocked buffer)', async () => {
    const store = memoryStore();
    await store.add([targetOf('poison', ['p'])], 100, 5, Date.now());
    await store.take(['poison'], 'poison-flush', Date.now());
    await store.add([targetOf('ref-1', ['a'])], 100, 5, Date.now() - 5000);
    const writes: string[] = [];
    const write = async (targets: DenormTarget[]) => {
      if (targets.some((t) => t.id === 'poison')) throw new Error('script_exception');
      writes.push(...targets.map((t) => t.id));
    };
    const buffer = createDenormBuffer(store, write, memoryLocker().locker, OPTIONS);
    await buffer.tick();
    expect(writes).toEqual(['ref-1']);
    await buffer.tick();
    await buffer.tick();
    expect(store.flights.size).toBe(0);
    expect([...store.dead.keys()]).toEqual(['poison-flush']);
    expect(store.total()).toBe(0);
  });

  it('should land the pending appends of a document before a removal on it', async () => {
    const store = memoryStore();
    const { writes, write } = recordingWriter();
    const buffer = createDenormBuffer(store, write, memoryLocker().locker, OPTIONS);
    await buffer.add([targetOf('ref-1', ['a'])]);
    await buffer.flushFirst(['ref-1', 'ref-2']);
    expect(idsOf(writes)).toEqual(['a']);
    await buffer.flushFirst(['ref-2']);
    expect(writes).toHaveLength(1);
  });

  it('should land the dead in-flight appends of a document before a removal on it (taken, never written)', async () => {
    const store = memoryStore();
    await store.add([targetOf('ref-1', ['a'])], 100, 5, Date.now());
    await store.take(['ref-1'], 'dead-flush', Date.now());
    const { writes, write } = recordingWriter();
    await createDenormBuffer(store, write, memoryLocker().locker, OPTIONS).flushFirst(['ref-1']);
    expect(writes).toEqual([{ targets: [targetOf('ref-1', ['a'])], replay: true }]);
    expect(store.flights.size).toBe(0);
  });

  it('should make a removal wait for a write in progress on its document (the append lands before the removal)', async () => {
    const store = memoryStore();
    const events: string[] = [];
    let release: () => void = () => {};
    const writeHeld = new Promise<void>((resolve) => {
      release = resolve;
    });
    const write = async (targets: DenormTarget[]) => {
      await writeHeld;
      events.push(`append ${targets.map((t) => t.id).join(',')}`);
    };
    const locks = memoryLocker();
    const buffer = createDenormBuffer(store, write, locks.locker, OPTIONS);
    await buffer.add([targetOf('ref-1', ['a'])]);
    const flushing = buffer.flush(['ref-1']);
    await new Promise((resolve) => {
      setTimeout(resolve, 5);
    });
    const removal = buffer.flushFirst(['ref-1']).then(() => events.push('remove ref-1'));
    await new Promise((resolve) => {
      setTimeout(resolve, 5);
    });
    expect(events, 'the removal waits for the write').toEqual([]);
    release();
    await Promise.all([flushing, removal]);
    expect(events).toEqual(['append ref-1', 'remove ref-1']);
  });

  it('should refuse the removal when the pending appends cannot be written (they would land after it)', async () => {
    const store = memoryStore();
    const { write } = recordingWriter(1);
    const buffer = createDenormBuffer(store, write, memoryLocker().locker, OPTIONS);
    await buffer.add([targetOf('ref-1', ['a'])]);
    await expect(buffer.flushFirst(['ref-1'])).rejects.toThrow('es down');
    expect(store.flights.size).toBe(1);
  });

  it('should flush everything pending at a graceful stop when it holds the lease, and leave the lease state reset', async () => {
    const store = memoryStore();
    const { writes, write } = recordingWriter();
    const buffer = createDenormBuffer(store, write, memoryLocker().locker, OPTIONS);
    await buffer.tick();
    expect(buffer.isLeased()).toBe(true);
    await buffer.add([targetOf('fresh', ['a'])]);
    await buffer.stop();
    expect(idsOf(writes)).toEqual(['a']);
    expect(buffer.isLeased()).toBe(false);
  });

  it('should bound the final flush of a graceful stop by its budget', async () => {
    const store = memoryStore();
    const write = async () => {
      await new Promise((resolve) => {
        setTimeout(resolve, 20);
      });
    };
    const buffer = createDenormBuffer(store, write, memoryLocker().locker, { ...OPTIONS, stopBudgetMs: 10 });
    await buffer.add([targetOf('r1', ['a']), targetOf('r2', ['b']), targetOf('r3', ['c']), targetOf('r4', ['d'])]);
    await buffer.stop();
    expect((await store.pending(['r1', 'r2', 'r3', 'r4'])).length).toBe(2);
  });

  it('should keep one tick chain whatever the number of starts', async () => {
    vi.useFakeTimers();
    const store = memoryStore();
    let ticks = 0;
    const acquire = store.acquireLease;
    store.acquireLease = async (token, ttlMs) => {
      ticks += 1;
      return acquire(token, ttlMs);
    };
    const buffer = createDenormBuffer(store, recordingWriter().write, memoryLocker().locker, OPTIONS);
    buffer.start();
    buffer.start();
    await vi.advanceTimersByTimeAsync(OPTIONS.flushPeriodMs / 2 * 4 + 10);
    expect(ticks).toBe(4);
    await buffer.stop();
    const afterStop = ticks;
    await vi.advanceTimersByTimeAsync(OPTIONS.flushPeriodMs * 4);
    expect(ticks, 'no tick after stop').toBe(afterStop);
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

  it('should write a flush with the same script parameters as the direct append, refreshed_at at the write time', () => {
    const before = new Date().toISOString();
    const [action, update] = denormTargetBulkLines(targetOf('ref-1', ['a', 'b'], '2020-01-01T00:00:00.000Z'), false) as any[];
    expect(action.update).toMatchObject({ _index: 'opencti_stix_meta_objects-000001', _id: 'ref-1' });
    // external-reference is a unidirectional meta ref: the direct path already adds its ids if absent
    expect(update.script.params.distinct_refs).toEqual([{ field: 'rel_external-reference.internal_id', ids: ['a', 'b'] }]);
    expect(update.script.params.appended_refs).toEqual([]);
    expect(update.script.params.timestamp_fields).toEqual(['refreshed_at']);
    // a buffered time would move refreshed_at back over a later direct write
    expect(update.script.params.updated_at >= before).toBe(true);
  });

  it('should buffer only unidirectional ref types, whose appends are contains-guarded (a write played twice cannot double an id)', () => {
    expect(bufferableRelations(['external-reference', 'object', 'created-by', 'targets'])).toEqual(['external-reference', 'created-by']);
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
