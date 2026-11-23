import { afterEach, describe, expect, it, vi } from 'vitest';
import { createDenormBuffer } from '../../../src/database/sequencer/denorm-buffer';
import type { DenormBufferStore, DenormEdit, DenormFlight, DenormIo, DenormTarget, DenormTombstones } from '../../../src/database/sequencer/denorm-buffer';
import { bufferableRelations, denormTargetBulkLines, toDenormTarget } from '../../../src/database/engine';

// task 0040 append buffer: the "to" side appends of hot documents (a misp external reference collects 26k citing
// ids, each append re-indexes its 1 MB document) wait in Redis and are written once per flush period per document.
// Removals edit the buffered appends instead of waiting for them. Each test names the lost, doubled, misordered or
// ghost append it guards against.

const OPTIONS = { flushPeriodMs: 1000, targetMaxIds: 5, maxIds: 100, flushBatch: 2, maxAttempts: 3, deadAfterMs: 60000 };

const targetOf = (id: string, ids: string[], updatedAt = '2026-11-20T10:00:00.000Z'): DenormTarget => ({
  id,
  index: 'opencti_stix_meta_objects-000001',
  docId: id,
  entityType: 'External-Reference',
  updatedAt,
  groups: [{ relation: 'external-reference', field: 'internal_id', ids }],
});
const removal = (docId: string, from: string): DenormEdit => ({ docId, relation: 'external-reference', field: 'internal_id', from, to: null });

const countOf = (targets: DenormTarget[]) => targets.reduce((n, t) => n + t.groups.reduce((m, g) => m + g.ids.length, 0), 0);
const copyOf = (targets: DenormTarget[]): DenormTarget[] => targets.map((t) => ({ ...t, groups: t.groups.map((g) => ({ ...g, ids: [...g.ids] })) }));

// In-memory store with the semantics of the Redis one (redis.ts redisDenormBufferStore): one set per document and
// field, a pending time per document, a total counting the ids until done or moved aside (in flight included),
// takes moved atomically into a flush that stays in flight until done, edits applied to pending, in-flight and
// moved aside appends and kept as tombstones while the document is in flight (until its last flush is done,
// cancelled for an id added again), failed writes counted per flush with the time of the first failure, flushes
// moved aside kept, with their marks, until requeued
const memoryStore = () => {
  const buffered = new Map<string, DenormTarget>();
  const pendingSince = new Map<string, number>();
  const flights = new Map<string, { at: number; targets: DenormTarget[]; attempts: number; failedAt?: number }>();
  const dead = new Map<string, { at: number; targets: DenormTarget[]; attempts: number }>();
  const marks = new Map<string, Set<string>>();
  const tombs = new Map<string, DenormEdit[]>();
  let total = 0;
  let lease: string | null = null;
  const release = (flushId: string, keep = false) => {
    const flight = flights.get(flushId);
    if (!flight) return;
    total -= countOf(flight.targets);
    if (!keep) {
      flight.targets.forEach((t) => {
        marks.get(t.id)?.delete(flushId);
        if ((marks.get(t.id)?.size ?? 0) === 0) tombs.delete(t.id);
      });
    }
    flights.delete(flushId);
  };
  const applyEdit = (target: DenormTarget | undefined, e: DenormEdit, counted: boolean) => {
    const group = target?.groups.find((g) => g.relation === e.relation && g.field === e.field);
    if (!group || !group.ids.includes(e.from)) return;
    group.ids = group.ids.filter((id) => id !== e.from);
    if (counted) total -= 1;
    if (e.to && !group.ids.includes(e.to)) {
      group.ids.push(e.to);
      if (counted) total += 1;
    }
  };
  const targetIn = (flushId: string, id: string) => (flights.get(flushId) ?? dead.get(flushId))?.targets.find((t) => t.id === id);
  const store: DenormBufferStore & {
    buffered: typeof buffered; flights: typeof flights; dead: typeof dead; tombs: typeof tombs;
    total: () => number; setLease: (t: string | null) => void; lease: () => string | null;
  } = {
    buffered,
    flights,
    dead,
    tombs,
    total: () => total,
    setLease: (t) => {
      lease = t;
    },
    lease: () => lease,
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
          const tomb = tombs.get(target.id);
          if (tomb) tombs.set(target.id, tomb.filter((e) => !(e.relation === group.relation && e.field === group.field && group.ids.includes(e.from))));
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
      return copyOf(taken);
    },
    done: async (flushId) => release(flushId),
    inflight: async (limit): Promise<DenormFlight[]> => [...flights.entries()].sort((a, b) => a[1].at - b[1].at).slice(0, limit)
      .map(([flushId, f]) => ({ flushId, docIds: f.targets.map((t) => t.id) })),
    flight: async (flushId) => {
      const flight = flights.get(flushId);
      return flight ? copyOf(flight.targets) : null;
    },
    edit: async (edits) => {
      edits.forEach((e) => {
        applyEdit(buffered.get(e.docId), e, true);
        const docMarks = marks.get(e.docId) ?? new Set<string>();
        docMarks.forEach((flushId) => applyEdit(targetIn(flushId, e.docId), e, flights.has(flushId)));
        if (docMarks.size > 0) tombs.set(e.docId, [...(tombs.get(e.docId) ?? []), e]);
      });
    },
    tombstones: async (ids): Promise<DenormTombstones[]> => ids.flatMap((id) => {
      const edits = tombs.get(id) ?? [];
      const flushId = [...(marks.get(id) ?? [])][0];
      const target = flushId ? targetIn(flushId, id) : undefined;
      return edits.length > 0 && target ? [{ id, index: target.index, docId: target.docId, edits }] : [];
    }),
    failed: async (flushId, maxAttempts, minAgeMs, nowMs) => {
      const flight = flights.get(flushId);
      if (!flight) return false;
      flight.attempts += 1;
      flight.failedAt = flight.failedAt ?? nowMs;
      if (flight.attempts < maxAttempts || nowMs - flight.failedAt < minAgeMs) return false;
      dead.set(flushId, { at: flight.at, targets: flight.targets, attempts: flight.attempts });
      release(flushId, true);
      return true;
    },
    deadCount: async () => dead.size,
    requeueDead: async (nowMs) => {
      const requeued = dead.size;
      dead.forEach((d, flushId) => {
        flights.set(flushId, { at: nowMs, targets: d.targets, attempts: 0 });
        total += countOf(d.targets);
      });
      dead.clear();
      return requeued;
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

// The engine side of the buffer: ES writes and tombstone erasures recorded, document locks never waited on
const memoryIo = (failures = 0) => {
  const writes: Array<{ targets: DenormTarget[]; replay: boolean }> = [];
  const erased: DenormTombstones[] = [];
  const events: string[] = [];
  const held = new Set<string>();
  let left = failures;
  let gate: Promise<void> | null = null;
  const io: DenormIo = {
    write: async (targets, replay) => {
      if (gate) await gate;
      if (left > 0) {
        left -= 1;
        throw new Error('es down');
      }
      writes.push({ targets, replay });
      events.push(`write ${targets.map((t) => t.id).join(',')}`);
    },
    erase: async (tombstones) => {
      erased.push(...tombstones);
      events.push(`erase ${tombstones.map((t) => t.edits.map((e) => e.from).join(',')).join(';')}`);
    },
    lock: async (ids) => {
      if (ids.some((id) => held.has(id))) return null;
      ids.forEach((id) => held.add(id));
      return { unlock: async () => ids.forEach((id) => held.delete(id)) };
    },
  };
  const holdWrites = () => {
    let release: () => void = () => {};
    gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    return () => {
      gate = null;
      release();
    };
  };
  return { io, writes, erased, events, held, holdWrites, failNext: (n: number) => {
    left = n;
  } };
};

const idsOf = (writes: Array<{ targets: DenormTarget[] }>) => writes.flatMap((w) => w.targets.flatMap((t) => t.groups.flatMap((g) => g.ids))).sort();
const wait = (ms: number) => new Promise((resolve) => {
  setTimeout(resolve, ms);
});

afterEach(() => {
  vi.useRealTimers();
});

describe('append buffer: buffering and periodic flush', () => {
  it('should write the appends of several batches to one document in one update, each id once (no rewrite per batch)', async () => {
    const store = memoryStore();
    const { io, writes } = memoryIo();
    const buffer = createDenormBuffer(store, io, OPTIONS);
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
    const { io } = memoryIo(1);
    const buffer = createDenormBuffer(store, io, { ...OPTIONS, maxIds: 2 });
    expect(await buffer.add([targetOf('ref-1', ['a', 'b'])])).toBe(true);
    // the write fails: the two ids stay in flight and still count
    expect(await buffer.flush(['ref-1'])).toBe(false);
    expect(await buffer.add([targetOf('ref-2', ['c'])])).toBe(false);
    expect(store.buffered.has('ref-2')).toBe(false);
  });

  it('should flush only the documents waiting longer than the flush period, and only on the lease holder', async () => {
    const store = memoryStore();
    const { io, writes } = memoryIo();
    const buffer = createDenormBuffer(store, io, OPTIONS);
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
    const { io, writes } = memoryIo();
    const buffer = createDenormBuffer(store, io, OPTIONS);
    await buffer.add([targetOf('hot', ['a', 'b', 'c', 'd', 'e'])]);
    await buffer.tick();
    expect(idsOf(writes)).toEqual(['a', 'b', 'c', 'd', 'e']);
  });

  it('should flush every due document across several flush batches in one tick', async () => {
    const store = memoryStore();
    const { io, writes } = memoryIo();
    const buffer = createDenormBuffer(store, io, OPTIONS);
    await store.add([targetOf('r1', ['a']), targetOf('r2', ['b']), targetOf('r3', ['c'])], 100, 5, Date.now() - 5000);
    await buffer.tick();
    expect(idsOf(writes)).toEqual(['a', 'b', 'c']);
    expect(store.buffered.size).toBe(0);
  });

  it('should stop flushing between batches once the lease is lost (one flusher at a time)', async () => {
    const store = memoryStore();
    const { io, writes } = memoryIo();
    const buffer = createDenormBuffer(store, io, OPTIONS);
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

  it('should leave the appends pending, not in flight, when their documents are busy, and stop the tick there (no spin)', async () => {
    const store = memoryStore();
    const { io, writes, held } = memoryIo();
    const buffer = createDenormBuffer(store, io, OPTIONS);
    await store.add([targetOf('r1', ['a']), targetOf('r2', ['b']), targetOf('r3', ['c'])], 100, 5, Date.now() - 5000);
    held.add('r1');
    const due = store.due;
    let reads = 0;
    store.due = async (beforeMs, limit) => {
      reads += 1;
      // a spinning tick never yields to the timers: fail it here rather than hang the run
      if (reads > 5) throw new Error('the tick spins on busy documents');
      return due(beforeMs, limit);
    };
    await buffer.tick();
    expect(writes).toHaveLength(0);
    expect(store.flights.size).toBe(0);
    expect(await store.pending(['r1', 'r2', 'r3'])).toEqual(['r1', 'r2', 'r3']);
    expect(reads).toBe(1);
  });
});

describe('append buffer: failures', () => {
  it('should replay its own failed flush at its next tick while it keeps the lease (no lost append on one node)', async () => {
    const store = memoryStore();
    const { io, writes } = memoryIo(1);
    const buffer = createDenormBuffer(store, io, OPTIONS);
    await store.add([targetOf('ref-1', ['a'])], 100, 5, Date.now() - 5000);
    await buffer.tick();
    expect(store.flights.size).toBe(1);
    await buffer.tick();
    expect(writes).toEqual([{ targets: [targetOf('ref-1', ['a'])], replay: true }]);
    expect(store.flights.size).toBe(0);
    expect(store.total()).toBe(0);
  });

  it('should stop a tick at the first failed batch, so that an outage does not take the whole backlog in flight', async () => {
    const store = memoryStore();
    const { io } = memoryIo(1);
    const buffer = createDenormBuffer(store, io, OPTIONS);
    await store.add([targetOf('r1', ['a']), targetOf('r2', ['b']), targetOf('r3', ['c']), targetOf('r4', ['d'])], 100, 5, Date.now() - 5000);
    await buffer.tick();
    expect(store.flights.size).toBe(1);
    expect((await store.pending(['r1', 'r2', 'r3', 'r4'])).length).toBe(2);
  });

  it('should replay a flush left by another node once its documents are free', async () => {
    const store = memoryStore();
    await store.add([targetOf('ref-1', ['a'])], 100, 5, Date.now());
    await store.take(['ref-1'], 'dead-node-flush', Date.now());
    const { io, writes } = memoryIo();
    await createDenormBuffer(store, io, OPTIONS).tick();
    expect(writes).toEqual([{ targets: [targetOf('ref-1', ['a'])], replay: true }]);
    expect(store.flights.size).toBe(0);
  });

  it('should not replay a flush whose documents are locked (its writer is still writing it)', async () => {
    const store = memoryStore();
    await store.add([targetOf('ref-1', ['a'])], 100, 5, Date.now());
    await store.take(['ref-1'], 'live-flush', Date.now());
    const { io, writes, held } = memoryIo();
    held.add('ref-1');
    await createDenormBuffer(store, io, OPTIONS).tick();
    expect(writes).toHaveLength(0);
    expect(store.flights.has('live-flush')).toBe(true);
  });

  it('should keep failing flushes in flight through an ES outage shorter than the dead letter delay, then land them', async () => {
    const store = memoryStore();
    const { io, writes, failNext } = memoryIo();
    const buffer = createDenormBuffer(store, io, OPTIONS);
    await store.add([targetOf('ref-1', ['a'])], 100, 5, Date.now() - 5000);
    failNext(6);
    for (let i = 0; i < 6; i += 1) await buffer.tick();
    expect(store.dead.size, 'an outage is not poison').toBe(0);
    await buffer.tick();
    expect(idsOf(writes)).toEqual(['a']);
    expect(store.total()).toBe(0);
  });

  it('should move a flush still failing after the dead letter delay aside and keep flushing the due documents (no blocked buffer)', async () => {
    const store = memoryStore();
    await store.add([targetOf('poison', ['p'])], 100, 5, Date.now());
    await store.take(['poison'], 'poison-flush', Date.now());
    await store.add([targetOf('ref-1', ['a'])], 100, 5, Date.now() - 5000);
    const written: string[] = [];
    const { io } = memoryIo();
    io.write = async (targets) => {
      if (targets.some((t) => t.id === 'poison')) throw new Error('script_exception');
      written.push(...targets.map((t) => t.id));
    };
    const buffer = createDenormBuffer(store, io, { ...OPTIONS, deadAfterMs: 0 });
    await buffer.tick();
    expect(written).toEqual(['ref-1']);
    await buffer.tick();
    await buffer.tick();
    expect(store.flights.size).toBe(0);
    expect([...store.dead.keys()]).toEqual(['poison-flush']);
    expect(store.total()).toBe(0);
  });

  it('should requeue what was moved aside at start and replay it', async () => {
    const store = memoryStore();
    await store.add([targetOf('ref-1', ['a'])], 100, 5, Date.now());
    await store.take(['ref-1'], 'f1', Date.now());
    expect(await store.failed('f1', 1, 0, Date.now())).toBe(true);
    const { io, writes } = memoryIo();
    const buffer = createDenormBuffer(store, io, OPTIONS);
    buffer.start();
    await wait(1);
    await buffer.stop();
    expect(store.dead.size).toBe(0);
    expect(writes).toEqual([{ targets: [targetOf('ref-1', ['a'])], replay: true }]);
  });
});

describe('append buffer: removals and merges edit the buffered appends', () => {
  it('should drop a removed id from the pending appends, so that the flush does not bring it back', async () => {
    const store = memoryStore();
    const { io, writes } = memoryIo();
    const buffer = createDenormBuffer(store, io, OPTIONS);
    await buffer.add([targetOf('ref-1', ['a', 'b'])]);
    await buffer.edit([removal('ref-1', 'a')]);
    await buffer.flush(['ref-1']);
    expect(idsOf(writes)).toEqual(['b']);
    expect(store.total()).toBe(0);
  });

  it('should drop a removed id from a dead in-flight flush, so that its replay does not bring it back', async () => {
    const store = memoryStore();
    await store.add([targetOf('ref-1', ['a', 'b'])], 100, 5, Date.now());
    await store.take(['ref-1'], 'dead-flush', Date.now());
    const { io, writes } = memoryIo();
    const buffer = createDenormBuffer(store, io, OPTIONS);
    await buffer.edit([removal('ref-1', 'a')]);
    await buffer.tick();
    expect(idsOf(writes)).toEqual(['b']);
  });

  it('should erase a removed id a write in progress landed, after that write and before the flush is done', async () => {
    const store = memoryStore();
    const { io, writes, erased, events, holdWrites } = memoryIo();
    const buffer = createDenormBuffer(store, io, OPTIONS);
    await buffer.add([targetOf('ref-1', ['a', 'b'])]);
    const release = holdWrites();
    const flushing = buffer.flush(['ref-1']);
    await wait(1);
    // the removal happens while the write, which read a and b, is in progress
    await buffer.edit([removal('ref-1', 'a')]);
    expect(store.tombs.get('ref-1')).toEqual([removal('ref-1', 'a')]);
    release();
    await flushing;
    expect(idsOf(writes)).toEqual(['a', 'b']);
    expect(erased).toEqual([{ id: 'ref-1', index: 'opencti_stix_meta_objects-000001', docId: 'ref-1', edits: [removal('ref-1', 'a')] }]);
    expect(events).toEqual(['write ref-1', 'erase a']);
    expect(store.tombs.has('ref-1'), 'tombstones go with the last flush').toBe(false);
  });

  it('should rename a merged id in the pending appends', async () => {
    const store = memoryStore();
    const { io, writes } = memoryIo();
    const buffer = createDenormBuffer(store, io, OPTIONS);
    await buffer.add([targetOf('ref-1', ['source', 'b'])]);
    await buffer.edit([{ ...removal('ref-1', 'source'), to: 'target' }]);
    await buffer.flush(['ref-1']);
    expect(idsOf(writes)).toEqual(['b', 'target']);
  });

  it('should drop a removed id from a flush moved aside, so that its requeue does not bring it back', async () => {
    const store = memoryStore();
    await store.add([targetOf('ref-1', ['a', 'b'])], 100, 5, Date.now());
    await store.take(['ref-1'], 'f1', Date.now());
    await store.failed('f1', 1, 0, Date.now());
    const { io, writes } = memoryIo();
    const buffer = createDenormBuffer(store, io, OPTIONS);
    await buffer.edit([removal('ref-1', 'a')]);
    expect(store.total(), 'ids moved aside are out of the total').toBe(0);
    await store.requeueDead(Date.now());
    await buffer.tick();
    expect(idsOf(writes)).toEqual(['b']);
    expect(store.total()).toBe(0);
  });

  it('should not erase an id added again after its removal, while an earlier flush of the document is still in flight', async () => {
    const store = memoryStore();
    // an earlier flush of the document failed and waits for its replay
    await store.add([targetOf('ref-1', ['old'])], 100, 5, Date.now());
    await store.take(['ref-1'], 'f1', Date.now());
    const { io, writes, erased } = memoryIo();
    const buffer = createDenormBuffer(store, io, OPTIONS);
    await buffer.add([targetOf('ref-1', ['a'])]);
    await buffer.edit([removal('ref-1', 'a')]);
    // the relation is created again
    await buffer.add([targetOf('ref-1', ['a'])]);
    await buffer.flush(['ref-1']);
    expect(idsOf(writes)).toEqual(['a']);
    expect(erased.flatMap((t) => t.edits.map((e) => e.from))).not.toContain('a');
  });

  it('should keep no tombstone for a document not in flight (nothing to erase later)', async () => {
    const store = memoryStore();
    const { io } = memoryIo();
    const buffer = createDenormBuffer(store, io, OPTIONS);
    await buffer.add([targetOf('ref-1', ['a'])]);
    await buffer.edit([removal('ref-1', 'a')]);
    expect(store.tombs.size).toBe(0);
  });
});

describe('append buffer: lifecycle', () => {
  it('should flush what is pending and replay what is in flight at a graceful stop, then release the lease and stop buffering', async () => {
    const store = memoryStore();
    const { io, writes } = memoryIo();
    const buffer = createDenormBuffer(store, io, OPTIONS);
    await store.add([targetOf('dead', ['d'])], 100, 5, Date.now());
    await store.take(['dead'], 'dead-flush', Date.now());
    buffer.start();
    expect(buffer.isBuffering()).toBe(true);
    await buffer.add([targetOf('fresh', ['a'])]);
    await buffer.stop();
    expect(idsOf(writes)).toEqual(['a', 'd']);
    expect(await store.acquireLease('another node', 1000), 'the lease is free').toBe(true);
    expect(buffer.isBuffering()).toBe(false);
  });

  it('should bound the final flush of a graceful stop by its budget', async () => {
    const store = memoryStore();
    const { io } = memoryIo();
    io.write = async () => {
      await wait(20);
    };
    const buffer = createDenormBuffer(store, io, { ...OPTIONS, stopBudgetMs: 10 });
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
    const buffer = createDenormBuffer(store, memoryIo().io, OPTIONS);
    buffer.start();
    buffer.start();
    await vi.advanceTimersByTimeAsync((OPTIONS.flushPeriodMs / 2) * 4 + 10);
    expect(ticks).toBe(4);
    await buffer.stop();
    const afterStop = ticks;
    await vi.advanceTimersByTimeAsync(OPTIONS.flushPeriodMs * 4);
    expect(ticks, 'no tick after stop').toBe(afterStop);
  });

  it('should wait for a running tick at stop, so that the tick cannot take the lease back once stop released it', async () => {
    vi.useFakeTimers();
    const store = memoryStore();
    await store.add([targetOf('r1', ['a']), targetOf('r2', ['b']), targetOf('r3', ['c'])], 100, 5, Date.now() - 5000);
    // the first tick is held in its lease renewal between two flush batches
    let calls = 0;
    let holdRenewal: (() => void) | null = null;
    const acquire = store.acquireLease;
    store.acquireLease = async (token, ttlMs) => {
      calls += 1;
      if (calls === 2) {
        await new Promise<void>((resolve) => {
          holdRenewal = resolve;
        });
      }
      return acquire(token, ttlMs);
    };
    let ticks = 0;
    const inflight = store.inflight;
    store.inflight = async (limit) => {
      ticks += 1;
      return inflight(limit);
    };
    const buffer = createDenormBuffer(store, memoryIo().io, OPTIONS);
    buffer.start();
    await vi.advanceTimersByTimeAsync(OPTIONS.flushPeriodMs / 2 + 1);
    expect(holdRenewal, 'the first tick is running').not.toBeNull();
    const stopping = buffer.stop();
    await vi.advanceTimersByTimeAsync(1);
    (holdRenewal as unknown as () => void)();
    await stopping;
    await vi.advanceTimersByTimeAsync(1);
    expect(store.lease(), 'the lease is free after stop').toBeNull();
    expect(store.buffered.size).toBe(0);
    const before = ticks;
    buffer.start();
    await vi.advanceTimersByTimeAsync((OPTIONS.flushPeriodMs / 2) * 4 + 10);
    expect(ticks - before, 'one tick chain after a restart').toBe(4);
    await buffer.stop();
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
