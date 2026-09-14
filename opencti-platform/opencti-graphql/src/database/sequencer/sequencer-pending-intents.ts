// POC ingestion sequencer: PENDING INTENTS (retry-gap option 1, user decision 2026-09-14).
// Extends strip-and-reconcile from EDGES to whole CREATIONS. A relation whose HARD reference
// (an endpoint) is still missing when its park deadline passes, or whose in-bundle producer
// is declared dead, used to be rejected and left to the worker's retry ladder (pycti: 1-3 s
// sleeps, ~20 attempts). On the chunk-queue path nothing retries it, and the first A/B lost
// 9-10% of the objects that way. The write itself is retained here instead, re-submitted
// through the normal boundary when its target lands (loop match after commit) or by the
// periodic sweeper, and expires VISIBLY, never silently.
//
// Same contract as sequencer-pending-refs: complete in-memory index of the pending
// population (byId + byTarget), ES store under the opencti* prefix (bench clean-state wipes
// it), write-through, hydrated at loop start. Records carry the serialized input, so the
// memory footprint is bounded by the cap below, not by the population's age.
import { createHash } from 'node:crypto';
import conf, { logApp } from '../../config/conf';
import { SEQUENCER_DEFERRED_ERROR } from '../../config/errors';
import { getInstanceIds } from '../../schema/identifier';
import { SEQUENCER_CONFIG } from './sequencer-config';
import { sequencerMetrics } from './sequencer-metrics';
import type { IntentKind, SequencerIntent } from './sequencer-intent';
import type { AuthUser } from '../../types/user';

export const PENDING_INTENTS_INDEX = 'opencti_sequencer_pending_intents';
const PENDING_INTENTS_MAX = Number(conf.get('app:ingestion_sequencer:pending_intents_max') ?? 200000);

export interface PendingIntentRecord {
  id: string; // sha(kind|type|user|stable input): a re-deferral upserts, never duplicates
  kind: IntentKind;
  type: string;
  input_json: string;
  opts_json: string;
  user_id: string;
  work_id?: string;
  missing_refs: string[]; // the unresolved ids AS GIVEN (stix / standard ids)
  created_at: number;
  updated_at: number;
  attempts: number;
  status: 'pending' | 'applied' | 'expired' | 'failed';
  // Original AuthUser, MEMORY-ONLY: keeps the creator attribution of the re-submitted
  // creation; records rehydrated after a restart are re-submitted as SYSTEM_USER with a
  // worker origin (documented divergence, same as pending refs).
  user?: AuthUser;
}

interface EsOps {
  indexExists: (index: string) => Promise<boolean>;
  createIndex: (index: string, mappingProperties: Record<string, any>) => Promise<any>;
  bulk: (body: any[]) => Promise<any>;
  search: (query: any) => Promise<any>;
}
let esOps: EsOps | null = null;
export const registerPendingIntentsEsOps = (ops: EsOps) => {
  esOps = ops;
};

// Registered by middleware (no import cycle): re-enters the boundary with the recorded
// input, so the creation is enqueued, batched and ordered like any intent.
type Resubmit = (record: PendingIntentRecord) => Promise<any>;
let resubmit: Resubmit | null = null;
export const registerPendingIntentResubmit = (fn: Resubmit) => {
  resubmit = fn;
};

// Registered by the chunk intake manager: terminal outcome of a retained creation, used
// for the work bookkeeping the manager skipped when the chunk was acked (applied = the
// expectation is met; expired / failed = met with an error).
type Settled = (record: PendingIntentRecord, error?: string) => Promise<void>;
let settledHook: Settled | null = null;
export const registerPendingIntentSettled = (fn: Settled) => {
  settledHook = fn;
};

const byId = new Map<string, PendingIntentRecord>();
const byTarget = new Map<string, Map<string, PendingIntentRecord>>();
let sweeper: ReturnType<typeof setInterval> | null = null;

const stableStringify = (value: any): string => {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(value[k])}`).join(',')}}`;
};

const recordKey = (kind: string, type: string, userId: string, input: Record<string, any>) => createHash('sha256')
  .update(`${kind}|${type}|${userId}|${stableStringify(input)}`).digest('hex');

const memoryAdd = (record: PendingIntentRecord) => {
  byId.set(record.id, record);
  record.missing_refs.forEach((ref) => {
    let bucket = byTarget.get(ref);
    if (!bucket) {
      bucket = new Map();
      byTarget.set(ref, bucket);
    }
    bucket.set(record.id, record);
  });
};

const memoryRemove = (record: PendingIntentRecord) => {
  byId.delete(record.id);
  record.missing_refs.forEach((ref) => {
    const bucket = byTarget.get(ref);
    if (bucket) {
      bucket.delete(record.id);
      if (bucket.size === 0) byTarget.delete(ref);
    }
  });
};

export const pendingIntentsCount = () => byId.size;

// The loop asks before retaining: no store, or population at the cap = reject as today.
export const pendingIntentsAccepting = () => esOps !== null && byId.size < PENDING_INTENTS_MAX;

const checkBulkResponse = (result: any, operation: string) => {
  if (result?.errors) {
    const firstError = (result.items ?? []).find((i: any) => (i.index ?? i.update)?.error);
    throw new Error(`pending intents ${operation} bulk failed: ${JSON.stringify((firstError?.index ?? firstError?.update)?.error)}`);
  }
};

const serializeOpts = (opts: Record<string, any> | undefined) => {
  try {
    return JSON.stringify(opts ?? {});
  } catch {
    return '{}';
  }
};

// Persist a batch of deferrals (write-through + memory). A creation already pending (same
// key: re-submission that missed again) is upserted with attempts + 1 and its refreshed
// missing set. Returns false when nothing could be retained (the loop then rejects as today).
export const deferIntents = async (deferrals: { intent: SequencerIntent; missing: string[] }[]): Promise<boolean> => {
  if (!esOps || deferrals.length === 0) return false;
  const now = Date.now();
  const records: PendingIntentRecord[] = [];
  deferrals.forEach(({ intent, missing }) => {
    const id = recordKey(intent.kind, intent.type, intent.user.id, intent.input);
    const existing = byId.get(id);
    if (existing) {
      memoryRemove(existing);
      records.push({
        ...existing,
        missing_refs: missing.length > 0 ? missing : existing.missing_refs,
        updated_at: now,
        attempts: existing.attempts + 1,
        status: 'pending',
        user: intent.user,
      });
      sequencerMetrics.pendingIntentEvent('redeferred');
    } else {
      records.push({
        id,
        kind: intent.kind,
        type: intent.type,
        input_json: JSON.stringify(intent.input),
        opts_json: serializeOpts(intent.opts),
        user_id: intent.user.id,
        work_id: intent.context?.workId,
        missing_refs: missing,
        created_at: now,
        updated_at: now,
        attempts: 0,
        status: 'pending',
        user: intent.user,
      });
      sequencerMetrics.pendingIntentEvent('deferred');
    }
  });
  const body = records.flatMap((r) => {
    const { id: _id, user: _user, ...persisted } = r;
    return [{ index: { _index: PENDING_INTENTS_INDEX, _id: r.id } }, persisted];
  });
  checkBulkResponse(await esOps.bulk(body), 'defer');
  records.forEach(memoryAdd);
  return true;
};

// Complete-index lookup, called for every committed element (O(1) per instance id).
export const matchLandedIntents = (element: any): PendingIntentRecord[] => {
  if (byTarget.size === 0 || !element?.internal_id) return [];
  const hits = new Map<string, PendingIntentRecord>();
  getInstanceIds(element).forEach((id: string) => {
    const bucket = byTarget.get(id);
    if (bucket) bucket.forEach((record) => hits.set(record.id, record));
  });
  return [...hits.values()];
};

const settle = async (record: PendingIntentRecord, status: PendingIntentRecord['status'], error?: string) => {
  memoryRemove(record);
  record.status = status;
  if (esOps) {
    const body = [{ update: { _index: PENDING_INTENTS_INDEX, _id: record.id } }, { doc: { status, attempts: record.attempts, updated_at: Date.now() } }];
    checkBulkResponse(await esOps.bulk(body), 'settle');
  }
  sequencerMetrics.pendingIntentEvent(status);
  if (settledHook) {
    try {
      await settledHook(record, error);
    } catch (err) {
      logApp.warn('[SEQUENCER] pending intent settled hook failed', { id: record.id, cause: String(err) });
    }
  }
};

// One re-submission. The creation re-enters the boundary; three outcomes:
//   - applied: settled, the work expectation is met through the hook;
//   - deferred again (SEQUENCER_DEFERRED): the loop re-recorded it (same key, attempts + 1),
//     nothing to do here;
//   - any other error: terminal and visible.
const resubmitOne = async (record: PendingIntentRecord) => {
  if (!byId.has(record.id) || !resubmit) return;
  sequencerMetrics.pendingIntentEvent('resubmitted');
  try {
    await resubmit(record);
    if (byId.has(record.id)) await settle(record, 'applied');
  } catch (err: any) {
    if (err?.extensions?.code === SEQUENCER_DEFERRED_ERROR) return;
    logApp.warn('[SEQUENCER] pending intent re-submission failed, terminal', {
      id: record.id, type: record.type, missing: record.missing_refs, attempts: record.attempts, cause: String(err),
    });
    if (byId.has(record.id)) await settle(record, 'failed', String(err?.message ?? err));
  }
};

// Fire-and-forget, sequential: never awaited by the loop.
let resubmitChain: Promise<void> = Promise.resolve();
export const fireResubmit = (records: PendingIntentRecord[]) => {
  records.forEach((record) => {
    resubmitChain = resubmitChain.then(() => resubmitOne(record));
  });
};

// Periodic sweeper: re-submits aged records (targets that arrived through non-sequencer
// paths or before a restart resolve inside the normal path), expires the old ones VISIBLY.
const SWEEP_INTERVAL_MS = 60_000;
const SWEEP_MIN_AGE_MS = 30_000;
const SWEEP_MAX_RESUBMITS = 500;
let sweeping = false;
const sweepOnce = async () => {
  if (sweeping) return;
  sweeping = true;
  const sweepStart = Date.now();
  let resubmitted = 0;
  let expired = 0;
  try {
    const now = Date.now();
    const aged = [...byId.values()].filter((r) => now - r.updated_at > SWEEP_MIN_AGE_MS);
    for (let i = 0; i < aged.length; i += 1) {
      const record = aged[i];
      if (now - record.created_at > SEQUENCER_CONFIG.pendingRefExpiryS * 1000) {
        logApp.warn('[SEQUENCER] pending intent EXPIRED without its reference', {
          id: record.id, type: record.type, missing: record.missing_refs, attempts: record.attempts,
        });
        await settle(record, 'expired', `Creation expired: reference(s) never landed: ${record.missing_refs.join(', ')}`);
        expired += 1;
      } else if (resubmitted < SWEEP_MAX_RESUBMITS) {
        await resubmitOne(record);
        resubmitted += 1;
      }
    }
    if (aged.length > 0) {
      logApp.info('[SEQUENCER] pending intents sweep', {
        swept: aged.length, resubmitted, expired, remaining: byId.size, duration_ms: Date.now() - sweepStart,
      });
    }
  } finally {
    sweeping = false;
  }
};

export const initPendingIntents = async () => {
  if (!esOps) {
    logApp.error('[SEQUENCER] pending intents: ES ops not registered, hard-ref retention disabled');
    return;
  }
  if (!(await esOps.indexExists(PENDING_INTENTS_INDEX))) {
    await esOps.createIndex(PENDING_INTENTS_INDEX, {
      kind: { type: 'keyword' },
      type: { type: 'keyword' },
      input_json: { type: 'text', index: false },
      opts_json: { type: 'text', index: false },
      user_id: { type: 'keyword' },
      work_id: { type: 'keyword' },
      missing_refs: { type: 'keyword' },
      created_at: { type: 'long' },
      updated_at: { type: 'long' },
      attempts: { type: 'integer' },
      status: { type: 'keyword' },
    });
  } else {
    let after: any[] | undefined;
    for (;;) {
      const query: any = {
        index: PENDING_INTENTS_INDEX,
        size: 2000,
        sort: [{ created_at: 'asc' }, { _shard_doc: 'asc' }],
        query: { term: { status: 'pending' } },
      };
      if (after) query.search_after = after;
      const result = await esOps.search(query);
      const searchHits = result?.hits?.hits ?? [];
      if (searchHits.length === 0) break;
      searchHits.forEach((h: any) => memoryAdd({ ...h._source, id: h._id }));
      after = searchHits[searchHits.length - 1].sort;
      if (searchHits.length < 2000) break;
    }
  }
  if (!sweeper) {
    sweeper = setInterval(() => {
      sweepOnce().catch((err) => logApp.error('[SEQUENCER] pending intents sweep failed', { cause: err }));
    }, SWEEP_INTERVAL_MS);
    if (typeof sweeper.unref === 'function') sweeper.unref();
  }
  logApp.info('[SEQUENCER] pending intents armed (hard-ref retention)', { pending: byId.size, max: PENDING_INTENTS_MAX });
};
