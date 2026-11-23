// task 0040 append buffer (work-kb opencti-denormalization-append-buffer-design). A relationship appends the id of
// each endpoint into a rel_* array of the other one (reverse denormalization, engine.ts elIndexElements), and an
// ES scripted update re-indexes the whole document: a misp external reference collects 26k citing ids (1 MB), so
// each append rewrote 1 MB. The "to" side appends of the buffered relationship types are kept in Redis at batch
// commit, one SET per document and field, and written once per flush period, one update per document. The
// relationship documents and the "from" side arrays are still written at commit; the references panel of a new
// object lags by up to 1.5 x the flush period (user decision 2026-11-20). Only a node whose intake manager
// initialized the buffer uses it (user decision 2026-11-21): everywhere else appends are direct.
// A take moves a document's ids out of the buffer atomically into an in-flight flush, deleted once ES acknowledged
// it. Writes of buffered appends hold a lock per document (the locker, a namespace of its own, never waited on): a
// flush whose documents can be locked is not being written, so the lease holder replays it at its next tick,
// contains-guarded since part of it may have landed. A flush still failing after a while is moved aside (dead
// letter, content kept), requeued at the next start.
// Removals never wait for the buffer (user decision 2026-11-23): once a relation delete has cleaned the ES arrays,
// it drops its ids from the document's pending, in-flight and moved aside appends, a merge renames them, in Redis.
// A write already in progress may still land a removed id: a ghost id in the reverse array, accepted (user decision
// 2026-11-23: not critical, the regardingOf readers keep an id only when its relationship exists). A failed flush is
// replayed with an exponential back-off.
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

// A removal (to null) or a merge rename (from -> to) of one id in one field of one document
export interface DenormEdit {
  docId: string; // internal id of the document
  relation: string;
  field: string;
  from: string;
  to: string | null;
}

export interface DenormRetry {
  baseMs: number;
  maxMs: number;
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
  // in-flight flushes that may be replayed at nowMs (taken, or past their retry time), oldest first
  inflight: (limit: number, nowMs: number) => Promise<DenormFlight[]>;
  // the appends of an in-flight flush, null once done or moved aside
  flight: (flushId: string) => Promise<DenormTarget[] | null>;
  // applies removals and renames to the pending, in-flight and moved aside appends
  edit: (edits: DenormEdit[]) => Promise<void>;
  // one more failed write: moved aside (true) once it failed maxAttempts times over at least minAgeMs, otherwise
  // replayed no earlier than its next retry
  failed: (flushId: string, maxAttempts: number, minAgeMs: number, nowMs: number, retry: DenormRetry) => Promise<boolean>;
  deadCount: () => Promise<number>;
  // the flushes moved aside go back in flight (replayed at the next tick), returns how many
  requeueDead: (nowMs: number) => Promise<number>;
  acquireLease: (token: string, ttlMs: number) => Promise<boolean>;
  releaseLease: (token: string) => Promise<void>;
}

export interface DenormLock {
  unlock: () => Promise<void>;
}

export interface DenormIo {
  // writes the appends to ES and refreshes; replay = contains-guarded (part of it may already be there)
  write: (targets: DenormTarget[], replay: boolean) => Promise<void>;
  // locks these documents for a write of their appends at once, null when one is busy
  lock: (ids: string[]) => Promise<DenormLock | null>;
}

export interface DenormBufferOptions {
  flushPeriodMs: number;
  targetMaxIds: number;
  maxIds: number;
  flushBatch: number; // documents per flush
  maxAttempts?: number; // failed writes before a flush can be moved aside
  deadAfterMs?: number; // and failing for at least that long: an ES outage alone does not move appends aside
  stopBudgetMs?: number; // time the final flush of a graceful stop may take
  replayBatch?: number; // in-flight flushes looked at per tick
  retryMaxMs?: number; // longest back-off between two replays of a failing flush
}

const countIds = (targets: DenormTarget[]) => targets.reduce((acc, t) => acc + t.groups.reduce((n, g) => n + g.ids.length, 0), 0);
// The targets with ids to write (removals may have emptied some)
const withIds = (targets: DenormTarget[]) => targets
  .map((t) => ({ ...t, groups: t.groups.filter((g) => g.ids.length > 0) }))
  .filter((t) => t.groups.length > 0);

export const createDenormBuffer = (store: DenormBufferStore, io: DenormIo, options: DenormBufferOptions) => {
  const token = uuidv4();
  const leaseTtlMs = Math.max(30000, options.flushPeriodMs * 3);
  const maxAttempts = options.maxAttempts ?? 5;
  const deadAfterMs = options.deadAfterMs ?? 30 * 60 * 1000;
  const stopBudgetMs = options.stopBudgetMs ?? 30000;
  const replayBatch = options.replayBatch ?? 20;
  const tickMs = Math.max(50, Math.floor(options.flushPeriodMs / 2));
  const retry = { baseMs: tickMs, maxMs: options.retryMaxMs ?? 5 * 60 * 1000 };
  let timer: NodeJS.Timeout | null = null;
  let running = false;
  let generation = 0;
  let ticking: Promise<void> | null = null;

  // false: over the global cap, the caller writes these appends directly
  const add = async (targets: DenormTarget[]): Promise<boolean> => {
    if (targets.length === 0) return true;
    const added = await store.add(targets, options.maxIds, options.targetMaxIds, Date.now());
    sequencerMetrics.denormBuffer(added ? 'buffered_ids' : 'fallback_ids', countIds(targets));
    return added;
  };

  // Removals and renames on the buffered appends (relation delete, merge), never waiting
  const edit = async (edits: DenormEdit[]) => {
    if (edits.length === 0) return;
    await store.edit(edits);
    sequencerMetrics.denormBuffer('edited_ids', edits.length);
  };

  // A failed write counts against the flush; once failing long enough it is moved aside and logged
  const recordFailure = async (flushId: string, targets: DenormTarget[], err: unknown) => {
    sequencerMetrics.denormBuffer('flush_failed');
    const movedAside = await store.failed(flushId, maxAttempts, deadAfterMs, Date.now(), retry);
    if (movedAside) {
      sequencerMetrics.denormBuffer('dead_targets', targets.length);
      logApp.error('[SEQUENCER] denorm buffer flush moved aside after repeated failures', { flushId, documents: targets.map((t) => t.id), cause: err });
    } else {
      logApp.warn('[SEQUENCER] denorm buffer flush failed, replayed after a back-off', { flushId, cause: err });
    }
  };

  // The write of a flush: the appends left (removals may have emptied some documents), then done
  const land = async (flushId: string, targets: DenormTarget[], replay: boolean) => {
    const written = withIds(targets);
    if (written.length > 0) await io.write(written, replay);
    await store.done(flushId);
  };

  // Takes and writes the appends of these documents. A failed write leaves the flush in flight (a next tick
  // replays it); busy documents leave the appends pending. Returns false when nothing could be done.
  const flush = async (ids: string[]): Promise<boolean> => {
    if (ids.length === 0) return true;
    const lock = await io.lock(ids);
    if (!lock) return false;
    const flushId = uuidv4();
    try {
      const taken = await store.take(ids, flushId, Date.now());
      if (taken.length === 0) return true;
      try {
        await land(flushId, taken, false);
      } catch (err) {
        await recordFailure(flushId, taken, err);
        return false;
      }
      sequencerMetrics.denormBuffer('flushed_targets', taken.length);
      sequencerMetrics.denormBuffer('flushed_ids', countIds(taken));
      return true;
    } finally {
      await lock.unlock();
    }
  };

  // A tick or a final flush goes on while its chain is current (no stop or restart since) and before its deadline
  const active = (chain: number, deadline: number) => chain === generation && Date.now() < deadline;

  // In-flight flushes whose documents can be locked and whose retry time has come are not being written: replayed,
  // each on its own, the lease renewed between two
  const replayInflight = async (chain: number, deadline: number) => {
    const flights = await store.inflight(replayBatch, Date.now());
    for (let i = 0; i < flights.length && active(chain, deadline); i += 1) {
      if (i > 0 && !(await store.acquireLease(token, leaseTtlMs))) break;
      const { flushId, docIds } = flights[i];
      const lock = await io.lock(docIds);
      if (lock) {
        try {
          const targets = await store.flight(flushId);
          if (targets !== null) {
            try {
              await land(flushId, targets, true);
              sequencerMetrics.denormBuffer('replayed_targets', targets.length);
            } catch (err) {
              await recordFailure(flushId, targets, err);
            }
          }
        } finally {
          await lock.unlock();
        }
      }
    }
  };

  // Flushes the due documents batch by batch while this node holds the lease (renewed between batches), until a
  // batch fails or finds its documents busy (an outage must not take the whole backlog in flight) or the deadline
  const flushDue = async (beforeMs: number, chain: number, deadline: number) => {
    let due = await store.due(beforeMs, options.flushBatch);
    while (due.length > 0 && active(chain, deadline)) {
      const progressed = await flush(due);
      sequencerMetrics.denormBuffer('flushes');
      if (!progressed || due.length < options.flushBatch) break;
      if (!(await store.acquireLease(token, leaseTtlMs))) break;
      due = await store.due(beforeMs, options.flushBatch);
    }
  };

  // One tick, bounded by one flush period: only the lease holder flushes; it replays the dead flushes first
  const tick = async () => {
    const chain = generation;
    const deadline = Date.now() + options.flushPeriodMs;
    if (!(await store.acquireLease(token, leaseTtlMs))) return;
    await replayInflight(chain, deadline);
    if (!(await store.acquireLease(token, leaseTtlMs))) return;
    await flushDue(Date.now() - options.flushPeriodMs, chain, deadline);
    const oldest = await store.oldestPendingMs();
    sequencerMetrics.denormBufferLag(oldest === null ? 0 : (Date.now() - oldest) / 1000);
    sequencerMetrics.denormBufferDead(await store.deadCount());
  };

  const schedule = (chain: number) => {
    if (!running || chain !== generation) return;
    timer = setTimeout(() => {
      timer = null;
      ticking = tick().catch((err) => {
        logApp.warn('[SEQUENCER] denorm buffer tick failed, retried at the next tick', { cause: err });
      }).finally(() => {
        ticking = null;
        schedule(chain);
      });
    }, tickMs);
  };

  // Idempotent: one timer chain whatever the number of starts; what was moved aside is tried again
  const start = () => {
    if (running) return;
    running = true;
    generation += 1;
    store.requeueDead(Date.now()).then((requeued) => {
      if (requeued > 0) logApp.warn('[SEQUENCER] denorm buffer flushes moved aside requeued', { requeued });
    }).catch((err) => logApp.warn('[SEQUENCER] denorm buffer requeue failed', { cause: err }));
    schedule(generation);
  };

  // Graceful stop: buffering ends, the running tick (bounded by one flush period, cut short by the new generation)
  // is awaited, what is pending is flushed within the stop budget when this node holds the lease, then the lease is
  // released
  const stop = async () => {
    running = false;
    generation += 1;
    const chain = generation;
    if (timer) clearTimeout(timer);
    timer = null;
    if (ticking) await ticking;
    let leased = false;
    try {
      leased = await store.acquireLease(token, leaseTtlMs);
      if (leased) {
        const deadline = Date.now() + stopBudgetMs;
        await replayInflight(chain, deadline);
        await flushDue(Number.MAX_SAFE_INTEGER, chain, deadline);
      }
    } catch (err) {
      logApp.warn('[SEQUENCER] denorm buffer final flush failed, left for the next lease holder', { cause: err });
    } finally {
      if (leased) await store.releaseLease(token).catch(() => {});
    }
  };

  // appends go to the buffer only while it runs
  const isBuffering = () => running;

  return { add, edit, flush, tick, start, stop, isBuffering };
};

export type DenormBuffer = ReturnType<typeof createDenormBuffer>;
