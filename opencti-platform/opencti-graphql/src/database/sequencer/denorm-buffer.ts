// task 0040 append buffer (work-kb opencti-denormalization-append-buffer-design). A relationship appends the id of
// each endpoint into a rel_* array of the other one (reverse denormalization, engine.ts elIndexElements), and an
// ES scripted update re-indexes the whole document: a misp external reference collects 26k citing ids (1 MB), so
// each append rewrote 1 MB. The "to" side appends of the buffered relationship types are kept in Redis at batch
// commit, one SET per document and field, and written once per flush period, one update per document. The
// relationship documents and the "from" side arrays are still written at commit; the references panel of a new
// object lags by up to 1.5 x the flush period (user decision 2026-11-20). Only a node whose intake manager
// initialized the buffer uses it (user decision 2026-11-21): everywhere else appends and removals are direct.
// Every write of buffered appends holds a lock per document (the locker, a namespace of its own) from before the
// take until the appends are acknowledged or given up: a take moves a document's ids out of the buffer atomically
// into an in-flight flush, deleted once ES acknowledged it. A flush whose documents can be locked is not being
// written, so any lease holder replays it at its next tick, contains-guarded since part of it may have landed; a
// flush failing too often is moved aside (dead letter, content kept) so that it never blocks the others.
// A removal (relation delete, merge) locks its documents first, so that it waits for a write in progress, then
// lands their pending and dead in-flight appends before it runs.
import { v4 as uuidv4 } from 'uuid';
import { logApp } from '../../config/conf';
import { sequencerMetrics } from './sequencer-metrics';

export interface DenormGroup {
  relation: string; // relationship type
  field: string; // internal_id or i_relations (inferred)
  ids: string[]; // ids of the other endpoints to append
}

// The appends waiting for one document
export interface DenormTarget {
  id: string; // internal id of the document receiving the appends
  index: string;
  docId: string;
  entityType: string;
  updatedAt: string; // time of the latest commit that buffered some (the write sets refreshed_at to its own time)
  groups: DenormGroup[];
}

export interface DenormFlight {
  flushId: string;
  docIds: string[];
}

export interface DenormBufferStore {
  // false, nothing added, when the buffer holds maxIds ids or more (in flight included); a document over
  // targetMaxIds is due at once
  add: (targets: DenormTarget[], maxIds: number, targetMaxIds: number, nowMs: number) => Promise<boolean>;
  // documents whose first pending append is older than beforeMs, oldest first
  due: (beforeMs: number, limit: number) => Promise<string[]>;
  pending: (ids: string[]) => Promise<string[]>;
  oldestPendingMs: () => Promise<number | null>;
  // moves the appends of these documents into the in-flight flush, returns them (documents without appends omitted)
  take: (ids: string[], flushId: string, nowMs: number) => Promise<DenormTarget[]>;
  // the flush landed: its appends leave the buffer
  done: (flushId: string) => Promise<void>;
  // in-flight flushes, oldest first, with their documents
  inflight: (limit: number) => Promise<DenormFlight[]>;
  // the appends of an in-flight flush, null once done or moved aside
  flight: (flushId: string) => Promise<DenormTarget[] | null>;
  // the in-flight flushes holding one of these documents
  inflightOf: (ids: string[]) => Promise<string[]>;
  // one more failed write of this flush; at maxAttempts it is moved aside (true), its appends leave the buffer
  failed: (flushId: string, maxAttempts: number, nowMs: number) => Promise<boolean>;
  acquireLease: (token: string, ttlMs: number) => Promise<boolean>;
  releaseLease: (token: string) => Promise<void>;
}

// Writes the appends to ES and refreshes; replay = contains-guarded (part of it may already be there)
export type DenormWriter = (targets: DenormTarget[], replay: boolean) => Promise<void>;

export interface DenormLock {
  unlock: () => Promise<void>;
}
// Locks these documents for a write of their appends; wait = false gives up at once. null when not acquired.
export type DenormLocker = (ids: string[], wait: boolean) => Promise<DenormLock | null>;

export interface DenormBufferOptions {
  flushPeriodMs: number;
  targetMaxIds: number;
  maxIds: number;
  flushBatch: number; // documents per flush
  maxAttempts?: number; // failed writes of a flush before it is moved aside
  stopBudgetMs?: number; // time the final flush of a graceful stop may take
  replayBatch?: number; // in-flight flushes looked at per tick
}

const countIds = (targets: DenormTarget[]) => targets.reduce((acc, t) => acc + t.groups.reduce((n, g) => n + g.ids.length, 0), 0);

export const createDenormBuffer = (store: DenormBufferStore, write: DenormWriter, locker: DenormLocker, options: DenormBufferOptions) => {
  const token = uuidv4();
  const leaseTtlMs = Math.max(30000, options.flushPeriodMs * 3);
  const maxAttempts = options.maxAttempts ?? 5;
  const stopBudgetMs = options.stopBudgetMs ?? 30000;
  const replayBatch = options.replayBatch ?? 20;
  let timer: NodeJS.Timeout | null = null;
  let running = false;
  let leased = false;

  // false: over the global cap, the caller writes these appends directly
  const add = async (targets: DenormTarget[]): Promise<boolean> => {
    if (targets.length === 0) return true;
    const added = await store.add(targets, options.maxIds, options.targetMaxIds, Date.now());
    sequencerMetrics.denormBuffer(added ? 'buffered_ids' : 'fallback_ids', countIds(targets));
    return added;
  };

  // A failed write counts against the flush; at maxAttempts it is moved aside and logged with its documents
  const recordFailure = async (flushId: string, targets: DenormTarget[], err: unknown): Promise<boolean> => {
    sequencerMetrics.denormBuffer('flush_failed');
    const movedAside = await store.failed(flushId, maxAttempts, Date.now());
    if (movedAside) {
      sequencerMetrics.denormBuffer('dead_targets', targets.length);
      logApp.error('[SEQUENCER] denorm buffer flush moved aside after repeated failures', { flushId, documents: targets.map((t) => t.id), cause: err });
    } else {
      logApp.warn('[SEQUENCER] denorm buffer flush failed, replayed at a next tick', { flushId, cause: err });
    }
    return movedAside;
  };

  // Writes an in-flight flush again, contains-guarded; its documents are locked by the caller. False when the
  // write failed and the flush stays in flight.
  const replayFlight = async (flushId: string): Promise<boolean> => {
    const targets = await store.flight(flushId);
    if (targets === null) return true; // landed or moved aside meanwhile
    try {
      if (targets.length > 0) await write(targets, true);
      await store.done(flushId);
      sequencerMetrics.denormBuffer('replayed_targets', targets.length);
      return true;
    } catch (err) {
      return recordFailure(flushId, targets, err);
    }
  };

  // Takes and writes the appends of these documents; lockHeld when the caller locked them already. A failed write
  // leaves the flush in flight (a next tick replays it), a lock not acquired leaves the appends pending.
  const flushLocked = async (ids: string[]): Promise<number> => {
    const flushId = uuidv4();
    const taken = await store.take(ids, flushId, Date.now());
    if (taken.length === 0) return 0;
    try {
      await write(taken, false);
      await store.done(flushId);
    } catch (err) {
      await recordFailure(flushId, taken, err);
      throw err;
    }
    sequencerMetrics.denormBuffer('flushed_targets', taken.length);
    sequencerMetrics.denormBuffer('flushed_ids', countIds(taken));
    return taken.length;
  };
  const flush = async (ids: string[]): Promise<number> => {
    if (ids.length === 0) return 0;
    const lock = await locker(ids, true);
    if (!lock) return 0;
    try {
      return await flushLocked(ids);
    } finally {
      await lock.unlock();
    }
  };

  // Before a removal on these documents: waits for a write in progress on them, then lands their dead in-flight
  // and pending appends. Throws when the documents cannot be locked or a write fails: the removal must not run.
  const flushFirst = async (ids: string[]) => {
    if (ids.length === 0) return;
    const lock = await locker(ids, true);
    if (!lock) throw new Error('[SEQUENCER] denorm buffer documents busy, removal refused');
    try {
      // locked: no write is in progress on these documents, their in-flight flushes are dead
      const flights = await store.inflightOf(ids);
      for (let i = 0; i < flights.length; i += 1) {
        if (!(await replayFlight(flights[i]))) throw new Error('[SEQUENCER] denorm buffer in-flight appends not written, removal refused');
      }
      const pending = await store.pending(ids);
      if (pending.length > 0) {
        const flushed = await flushLocked(pending);
        sequencerMetrics.denormBuffer('flush_first_targets', flushed);
      }
    } finally {
      await lock.unlock();
    }
  };

  // In-flight flushes whose documents can be locked are not being written: replayed, each on its own
  const replayInflight = async () => {
    const flights = await store.inflight(replayBatch);
    for (let i = 0; i < flights.length; i += 1) {
      const { flushId, docIds } = flights[i];
      const lock = await locker(docIds, false);
      if (lock) {
        try {
          await replayFlight(flushId);
        } finally {
          await lock.unlock();
        }
      }
    }
  };

  // Flushes the due documents batch by batch while this node holds the lease (renewed between batches) and the
  // deadline is not passed
  const flushDue = async (beforeMs: number, deadline = Infinity) => {
    let due = await store.due(beforeMs, options.flushBatch);
    while (due.length > 0 && Date.now() < deadline) {
      // a failed write is counted and logged by flush, its flush stays in flight: the other batches go on
      await flush(due).catch(() => {});
      sequencerMetrics.denormBuffer('flushes');
      if (due.length < options.flushBatch) break;
      if (!(await store.acquireLease(token, leaseTtlMs))) {
        leased = false;
        break;
      }
      due = await store.due(beforeMs, options.flushBatch);
    }
  };

  // One tick: only the lease holder flushes; it replays the dead flushes first, at every tick
  const tick = async () => {
    const holds = await store.acquireLease(token, leaseTtlMs);
    leased = holds;
    if (!holds) return;
    await replayInflight();
    await flushDue(Date.now() - options.flushPeriodMs);
    const oldest = await store.oldestPendingMs();
    sequencerMetrics.denormBufferLag(oldest === null ? 0 : (Date.now() - oldest) / 1000);
  };

  const schedule = () => {
    if (!running) return;
    timer = setTimeout(() => {
      timer = null;
      tick().catch((err) => {
        sequencerMetrics.denormBuffer('flush_failed');
        logApp.warn('[SEQUENCER] denorm buffer tick failed, retried at the next tick', { cause: err });
      }).finally(schedule);
    }, Math.max(50, Math.floor(options.flushPeriodMs / 2)));
  };

  // Idempotent: one timer chain whatever the number of starts
  const start = () => {
    if (running) return;
    running = true;
    if (!timer) schedule();
  };

  // Graceful stop: what is pending is flushed now, within the stop budget, when this node holds the lease
  const stop = async () => {
    running = false;
    if (timer) clearTimeout(timer);
    timer = null;
    try {
      if (await store.acquireLease(token, leaseTtlMs)) {
        await replayInflight();
        await flushDue(Number.MAX_SAFE_INTEGER, Date.now() + stopBudgetMs);
        await store.releaseLease(token);
      }
    } catch (err) {
      logApp.warn('[SEQUENCER] denorm buffer final flush failed, left for the next lease holder', { cause: err });
    } finally {
      leased = false;
    }
  };

  const isLeased = () => leased;

  return { add, flush, flushFirst, tick, start, stop, isLeased };
};

export type DenormBuffer = ReturnType<typeof createDenormBuffer>;
