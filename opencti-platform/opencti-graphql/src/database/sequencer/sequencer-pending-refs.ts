// POC ingestion sequencer: strip-and-reconcile (plan 0009 s9.12.3, AGGRESSIVE variant;
// full design in the work-kb note opencti-strip-and-reconcile-design). A write whose
// optional ref cannot be resolved is ACCEPTED immediately and the missing edge becomes a
// PENDING REF record instead of a silent drop (the stock reject-twice-then-drop lost the
// edge forever: write-path reference verdict 30). The single-writer loop matches every
// committed element against the pending population and re-asserts the edge through the
// normal ref-add path; a periodic sweeper retries aged records and expires them VISIBLY.
//
// Memory contract (design note, "Memory-side decisions"): the in-memory structure is a
// COMPLETE derived index of the pending population, never an LRU: a memory miss certifies
// "no debt" with zero store queries on the hot path. Hydrated from the store at loop
// start, write-through afterwards. The store index lives under the opencti* prefix on
// purpose: the bench clean-state wipes it with the rest of the estate (fresh runs).
import { createHash } from 'node:crypto';
import { logApp } from '../../config/conf';
import { getInstanceIds } from '../../schema/identifier';
import { SEQUENCER_CONFIG } from './sequencer-config';
import { sequencerMetrics } from './sequencer-metrics';

export const PENDING_REFS_INDEX = 'opencti_sequencer_pending_refs';

export interface PendingRefRecord {
  id: string; // sha(owner|relType|target): natural dedup, re-strips overwrite
  owner_id: string;
  owner_type: string;
  rel_type: string; // database relationship type (e.g. 'object'), ready for createRelation
  target_ref: string; // the unresolved id AS GIVEN (standard/stix id or alias)
  user_id: string;
  created_at: number;
  attempts: number;
  status: 'pending' | 'reconciled' | 'expired' | 'void';
  // Original AuthUser, MEMORY-ONLY (never persisted): keeps the reconciled edge's creator
  // attribution identical to a normal write. After a restart the rehydrated records lose
  // it and the sweeper re-asserts as SYSTEM_USER (documented divergence).
  user?: any;
}

export interface StrippedRefInput {
  ownerId: string;
  ownerType: string;
  relType: string;
  targetRef: string;
  userId: string;
  user?: any;
}

// Registered by middleware at module load (no import cycle: this module never imports
// middleware). The assert replays the edge through the normal ref-add path (idempotent:
// an already-existing edge upserts to a no-op).
type ReconcileAssert = (record: PendingRefRecord, targetInternalId: string) => Promise<void>;
let reconcileAssert: ReconcileAssert | null = null;
export const registerReconcileAssert = (fn: ReconcileAssert) => {
  reconcileAssert = fn;
};

// ES access, registered by the loop from engine helpers (avoids a static import cycle
// engine -> middleware -> loop -> pending-refs -> engine).
interface EsOps {
  indexExists: (index: string) => Promise<boolean>;
  createIndex: (index: string, mappingProperties: Record<string, any>) => Promise<any>;
  bulk: (body: any[]) => Promise<any>;
  search: (query: any) => Promise<any>;
}
let esOps: EsOps | null = null;
export const registerPendingRefsEsOps = (ops: EsOps) => {
  esOps = ops;
};

// Per-apply sink for stripped refs (same module-holder pattern as the write buffer: the
// batch loop applies intents SERIALLY, so a single slot is race-free). applyGroup arms it
// around each leader.apply(); inputResolveRefs pushes into it when stripping. A slot
// carried on the context does NOT work: the 'applying' scoped context is a spread COPY
// built inside the apply closure, so the loop never sees what middleware writes on it
// (first validation campaign: strips fired, zero records persisted, refs lost).
export interface StrippedRef { targetRef: string; relType: string }
let currentStripSink: StrippedRef[] | null = null;
export const setCurrentStripSink = (sink: StrippedRef[] | null) => {
  currentStripSink = sink;
};
export const getCurrentStripSink = () => currentStripSink;

const byTarget = new Map<string, Map<string, PendingRefRecord>>();
const byId = new Map<string, PendingRefRecord>();
let sweeper: ReturnType<typeof setInterval> | null = null;

const recordKey = (ownerId: string, relType: string, targetRef: string) => createHash('sha256')
  .update(`${ownerId}|${relType}|${targetRef}`).digest('hex');

const memoryAdd = (record: PendingRefRecord) => {
  byId.set(record.id, record);
  let bucket = byTarget.get(record.target_ref);
  if (!bucket) {
    bucket = new Map();
    byTarget.set(record.target_ref, bucket);
  }
  bucket.set(record.id, record);
};

const memoryRemove = (record: PendingRefRecord) => {
  byId.delete(record.id);
  const bucket = byTarget.get(record.target_ref);
  if (bucket) {
    bucket.delete(record.id);
    if (bucket.size === 0) byTarget.delete(record.target_ref);
  }
};

export const pendingRefsCount = () => byId.size;

export const buildPendingRecords = (inputs: StrippedRefInput[]): PendingRefRecord[] => {
  const now = Date.now();
  return inputs.map((s) => ({
    id: recordKey(s.ownerId, s.relType, s.targetRef),
    owner_id: s.ownerId,
    owner_type: s.ownerType,
    rel_type: s.relType,
    target_ref: s.targetRef,
    user_id: s.userId,
    created_at: now,
    attempts: 0,
    status: 'pending' as const,
    user: s.user,
  }));
};

// Persist a batch of strip records (store write-through + memory index). Called by the
// loop right after a successful batch flush: the debt commits with the batch (small
// crash window between the two bulks, documented in the design note).
// The platform index template is dynamic:strict: the persisted document must carry ONLY
// mapped fields (validation campaign 2: the record's `id` field 400'd every item and the
// bulk does not throw on per-item errors, so the whole store stayed silently empty).
const checkBulkResponse = (response: any, operation: string) => {
  const result = response?.body ?? response;
  if (result?.errors) {
    const firstError = (result.items ?? []).find((i: any) => (i.index ?? i.update)?.error);
    logApp.error('[SEQUENCER] pending refs bulk rejected items', {
      operation, sample: (firstError?.index ?? firstError?.update)?.error,
    });
  }
};

export const persistPendingRecords = async (records: PendingRefRecord[]) => {
  if (records.length === 0 || !esOps) return;
  const body = records.flatMap((r) => {
    const { id: _id, user: _user, ...persisted } = r; // id is the _id; user is memory-only
    return [{ index: { _index: PENDING_REFS_INDEX, _id: r.id } }, persisted];
  });
  checkBulkResponse(await esOps.bulk(body), 'persist');
  records.forEach((r) => {
    if (!byId.has(r.id)) sequencerMetrics.pendingRefEvent('stripped');
    memoryAdd(r);
  });
};

// Complete-index lookup: called for every committed element (O(1) per instance id).
export const matchCreatedElement = (element: any): { record: PendingRefRecord; targetInternalId: string }[] => {
  if (byTarget.size === 0 || !element?.internal_id) return [];
  const hits: { record: PendingRefRecord; targetInternalId: string }[] = [];
  getInstanceIds(element).forEach((id: string) => {
    const bucket = byTarget.get(id);
    if (bucket) {
      bucket.forEach((record) => hits.push({ record, targetInternalId: element.internal_id }));
    }
  });
  return hits;
};

const settle = async (record: PendingRefRecord, status: PendingRefRecord['status']) => {
  memoryRemove(record);
  record.status = status;
  if (esOps) {
    const body = [{ update: { _index: PENDING_REFS_INDEX, _id: record.id } }, { doc: { status, attempts: record.attempts } }];
    checkBulkResponse(await esOps.bulk(body), 'settle');
  }
};

const bumpAttempts = async (record: PendingRefRecord) => {
  record.attempts += 1;
  if (esOps) {
    const body = [{ update: { _index: PENDING_REFS_INDEX, _id: record.id } }, { doc: { attempts: record.attempts } }];
    checkBulkResponse(await esOps.bulk(body), 'bump');
  }
};

// Fire-and-forget re-assertion (bounded, sequential): the createRelation goes back
// through the boundary as a NORMAL mutation, so it lands in the sequencer queue and is
// batched/ordered/deduped like any intent. Never awaited by the loop.
let reconcileChain: Promise<void> = Promise.resolve();
export const fireReconcile = (hits: { record: PendingRefRecord; targetInternalId: string }[]) => {
  hits.forEach(({ record, targetInternalId }) => {
    reconcileChain = reconcileChain.then(async () => {
      if (!byId.has(record.id) || !reconcileAssert) return; // already settled
      try {
        await reconcileAssert(record, targetInternalId);
        await settle(record, 'reconciled');
        sequencerMetrics.pendingRefEvent('reconciled');
      } catch (err) {
        await bumpAttempts(record);
        logApp.warn('[SEQUENCER] pending ref re-assertion failed, left to the sweeper', {
          id: record.id, rel_type: record.rel_type, target: record.target_ref, attempts: record.attempts, cause: String(err),
        });
      }
    });
  });
};

// Periodic sweeper: optimistic re-assertion of aged records (covers targets that arrived
// through non-sequencer paths or before a restart: the assert itself resolves the target
// by any of its ids, and throws MISSING_REFERENCE if it is still absent); records past
// the expiry go TERMINAL and visible, never silently dropped.
const SWEEP_INTERVAL_MS = 60_000;
const SWEEP_MIN_AGE_MS = 30_000;
let sweeping = false; // sweeps can outlast the interval: never overlap them
const sweepOnce = async () => {
  if (sweeping) return;
  sweeping = true;
  const sweepStart = Date.now();
  let reconciled = 0;
  let failed = 0;
  let failSample: unknown = null;
  try {
    const now = Date.now();
    const aged = [...byId.values()].filter((r) => now - r.created_at > SWEEP_MIN_AGE_MS);
    for (let i = 0; i < aged.length; i += 1) {
      const record = aged[i];
      if (now - record.created_at > SEQUENCER_CONFIG.pendingRefExpiryS * 1000) {
        await settle(record, 'expired');
        sequencerMetrics.pendingRefEvent('expired');
        logApp.warn('[SEQUENCER] pending ref EXPIRED without target', {
          id: record.id, owner: record.owner_id, rel_type: record.rel_type, target: record.target_ref, attempts: record.attempts,
        });
      } else if (reconcileAssert) {
        try {
          // target resolution happens inside the normal path (by any instance id)
          await reconcileAssert(record, record.target_ref);
          await settle(record, 'reconciled');
          sequencerMetrics.pendingRefEvent('reconciled');
          reconciled += 1;
        } catch (err) {
          await bumpAttempts(record);
          failed += 1;
          if (!failSample) failSample = { rel_type: record.rel_type, target: record.target_ref, attempts: record.attempts, cause: String(err) };
        }
      }
    }
    if (aged.length > 0) {
      logApp.info('[SEQUENCER] pending refs sweep', {
        swept: aged.length, reconciled, failed, remaining: byId.size, duration_ms: Date.now() - sweepStart, fail_sample: failSample,
      });
    }
  } finally {
    sweeping = false;
  }
};

export const initPendingRefs = async () => {
  if (!esOps) {
    logApp.error('[SEQUENCER] pending refs: ES ops not registered, strip-and-reconcile disabled');
    return;
  }
  if (!(await esOps.indexExists(PENDING_REFS_INDEX))) {
    await esOps.createIndex(PENDING_REFS_INDEX, {
      owner_id: { type: 'keyword' },
      owner_type: { type: 'keyword' },
      rel_type: { type: 'keyword' },
      target_ref: { type: 'keyword' },
      user_id: { type: 'keyword' },
      created_at: { type: 'long' },
      attempts: { type: 'integer' },
      status: { type: 'keyword' },
    });
  } else {
    // rehydrate the complete index (search_after pages; population is small by design)
    let after: any[] | undefined;
    for (;;) {
      const query: any = {
        index: PENDING_REFS_INDEX,
        size: 5000,
        sort: [{ created_at: 'asc' }, { _shard_doc: 'asc' }],
        query: { term: { status: 'pending' } },
      };
      if (after) query.search_after = after;
      const result = await esOps.search(query);
      const searchHits = result?.hits?.hits ?? [];
      if (searchHits.length === 0) break;
      searchHits.forEach((h: any) => memoryAdd({ ...h._source, id: h._id }));
      after = searchHits[searchHits.length - 1].sort;
      if (searchHits.length < 5000) break;
    }
  }
  if (!sweeper) {
    sweeper = setInterval(() => {
      sweepOnce().catch((err) => logApp.error('[SEQUENCER] pending refs sweep failed', { cause: err }));
    }, SWEEP_INTERVAL_MS);
    if (typeof sweeper.unref === 'function') sweeper.unref();
  }
  logApp.info('[SEQUENCER] strip-and-reconcile armed', { pending: byId.size });
};
