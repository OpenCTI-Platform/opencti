// task 0040 append buffer (work-kb opencti-denormalization-append-buffer-design). A relationship appends the id of
// each endpoint into a rel_* array of the other one (reverse denormalization, engine.ts elIndexElements), and an
// ES scripted update re-indexes the whole document: a misp external reference collects 26k citing ids (1 MB), so
// each append rewrote 1 MB. The "to" side appends of the buffered relationship types are kept in Redis at batch
// commit, one SET per document and field, and written once per flush period, one update per document. The
// relationship documents and the "from" side arrays are still written at commit; the references panel of a new
// object lags by up to the flush period (user decision 2026-11-20).
// Any node flushes the due documents while it holds the flush lease. A take moves a document's ids out of the
// buffer atomically into an in-flight flush, deleted once ES acknowledged it: a flush that died in between is
// replayed by the next lease holder, with a contains-guarded script since part of it may have landed. A removal
// (relation delete, merge) flushes its document first, so that it never runs before an append it follows.
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
  updatedAt: string; // refreshed_at the appends set (the latest commit that buffered some)
  groups: DenormGroup[];
}

export interface DenormInflight {
  flushId: string;
  targets: DenormTarget[];
}

export interface DenormBufferStore {
  // false, nothing added, when the buffer holds maxIds ids or more; a document over targetMaxIds is due at once
  add: (targets: DenormTarget[], maxIds: number, targetMaxIds: number, nowMs: number) => Promise<boolean>;
  // documents whose first pending append is older than beforeMs, oldest first
  due: (beforeMs: number, limit: number) => Promise<string[]>;
  pending: (ids: string[]) => Promise<string[]>;
  oldestPendingMs: () => Promise<number | null>;
  // moves the appends of these documents into the in-flight flush, returns them (documents without appends omitted)
  take: (ids: string[], flushId: string, nowMs: number) => Promise<DenormTarget[]>;
  done: (flushId: string) => Promise<void>;
  // in-flight flushes taken before beforeMs (their taker is presumed dead)
  inflight: (beforeMs: number) => Promise<DenormInflight[]>;
  acquireLease: (token: string, ttlMs: number) => Promise<boolean>;
  releaseLease: (token: string) => Promise<void>;
}

// Writes the appends to ES and refreshes; replay = contains-guarded (part of it may already be there)
export type DenormWriter = (targets: DenormTarget[], replay: boolean) => Promise<void>;

export interface DenormBufferOptions {
  flushPeriodMs: number;
  targetMaxIds: number;
  maxIds: number;
  flushBatch: number; // documents per flush
}

const countIds = (targets: DenormTarget[]) => targets.reduce((acc, t) => acc + t.groups.reduce((n, g) => n + g.ids.length, 0), 0);

export const createDenormBuffer = (store: DenormBufferStore, write: DenormWriter, options: DenormBufferOptions) => {
  const token = uuidv4();
  const leaseTtlMs = Math.max(30000, options.flushPeriodMs * 3);
  let timer: NodeJS.Timeout | null = null;
  let stopped = false;
  let leased = false;

  // false: over the global cap, the caller writes these appends directly
  const add = async (targets: DenormTarget[]): Promise<boolean> => {
    if (targets.length === 0) return true;
    const added = await store.add(targets, options.maxIds, options.targetMaxIds, Date.now());
    sequencerMetrics.denormBuffer(added ? 'buffered_ids' : 'fallback_ids', countIds(targets));
    return added;
  };

  // A failed write leaves the flush in flight: the next lease holder replays it
  const flush = async (ids: string[]): Promise<number> => {
    if (ids.length === 0) return 0;
    const flushId = uuidv4();
    const taken = await store.take(ids, flushId, Date.now());
    if (taken.length > 0) {
      await write(taken, false);
      sequencerMetrics.denormBuffer('flushed_targets', taken.length);
      sequencerMetrics.denormBuffer('flushed_ids', countIds(taken));
    }
    await store.done(flushId);
    return taken.length;
  };

  // Before a removal on these documents: their pending appends land first
  const flushFirst = async (ids: string[]) => {
    if (ids.length === 0) return;
    const pending = await store.pending(ids);
    if (pending.length === 0) return;
    const flushed = await flush(pending);
    sequencerMetrics.denormBuffer('flush_first_targets', flushed);
  };

  const replayInflight = async () => {
    const inflight = await store.inflight(Date.now() - leaseTtlMs);
    for (let i = 0; i < inflight.length; i += 1) {
      const { flushId, targets } = inflight[i];
      if (targets.length > 0) await write(targets, true);
      await store.done(flushId);
      sequencerMetrics.denormBuffer('replayed_targets', targets.length);
    }
  };

  const flushDue = async (beforeMs: number) => {
    let due = await store.due(beforeMs, options.flushBatch);
    while (due.length > 0) {
      await flush(due);
      sequencerMetrics.denormBuffer('flushes');
      if (due.length < options.flushBatch) break;
      due = await store.due(beforeMs, options.flushBatch);
    }
  };

  // One tick: only the lease holder flushes; a fresh holder replays the dead flushes first
  const tick = async () => {
    const holds = await store.acquireLease(token, leaseTtlMs);
    if (!holds) {
      leased = false;
      return;
    }
    if (!leased) await replayInflight();
    leased = true;
    await flushDue(Date.now() - options.flushPeriodMs);
    const oldest = await store.oldestPendingMs();
    sequencerMetrics.denormBufferLag(oldest === null ? 0 : (Date.now() - oldest) / 1000);
  };

  const schedule = () => {
    if (stopped) return;
    timer = setTimeout(() => {
      tick().catch((err) => {
        sequencerMetrics.denormBuffer('flush_failed');
        logApp.error('[SEQUENCER] denorm buffer flush failed, retried next tick', { cause: err });
      }).finally(schedule);
    }, Math.max(50, Math.floor(options.flushPeriodMs / 2)));
  };

  const start = () => {
    stopped = false;
    schedule();
  };

  // Graceful stop: everything pending is flushed now when this node holds the lease
  const stop = async () => {
    stopped = true;
    if (timer) clearTimeout(timer);
    timer = null;
    try {
      if (await store.acquireLease(token, leaseTtlMs)) {
        await flushDue(Number.MAX_SAFE_INTEGER);
        await store.releaseLease(token);
      }
    } catch (err) {
      logApp.error('[SEQUENCER] denorm buffer final flush failed, left for the next lease holder', { cause: err });
    }
  };

  return { add, flush, flushFirst, tick, start, stop };
};

export type DenormBuffer = ReturnType<typeof createDenormBuffer>;
