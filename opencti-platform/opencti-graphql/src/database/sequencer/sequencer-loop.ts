// POC ingestion sequencer (plan 0009, Stages B3/B5, C1/C2/C6, D1-D6). Two modes:
//   - passthrough (Stage B): one intent at a time through the unchanged path, concurrency 1.
//     Measures the sequential floor; no cache, no batching.
//   - batch (Stages C/D): self-clocking group commit. Per cycle:
//       assemble (residual deferred + unparked + drained queue, round-robin per source)
//       -> pre-resolve the whole batch (C2: at most 2 searches + 1 with-refs load)
//       -> plan (D1 phases, D2 dependency edges and parking, D3 coalescing, P2 chains)
//       -> ONE batch lock over the predicted key set (D4; nested lock sites no-op on held
//          keys through args.sequencer, real-lock only the unpredicted rest)
//       -> apply leaders one at a time (C6), absorbed intents share the leader's result,
//          own writes registered in the map for same-batch consumers (read-your-writes)
//       -> commit: evict own-written ids (D4a), unlock, re-park survivors.
// Parked intents rejoin every later batch until their reference resolves or their deadline
// passes (then they apply through the unchanged path, which behaves exactly as today).
// Errors are caught per intent and rejected on its promise: the GraphQL error contract is
// unchanged. Fail-open watchdog: a dead loop sends every later submit direct and logs.
import conf, { logApp } from '../../config/conf';
import { MissingReferenceFinalError } from '../../config/errors';
import { executionContext, SYSTEM_USER } from '../../utils/access';
import { generateStandardId, getInputIds, getInstanceIds } from '../../schema/identifier';
import { idLabel } from '../../schema/schema-labels';
import { schemaRelationsRefDefinition } from '../../schema/schema-relationsRef';
import { INPUT_EXTERNAL_REFS, INPUT_KILLCHAIN, INPUT_LABELS } from '../../schema/general';
import { ENTITY_TYPE_EXTERNAL_REFERENCE, ENTITY_TYPE_KILL_CHAIN_PHASE, ENTITY_TYPE_LABEL } from '../../schema/stixMetaObject';
import { elCreateIndex, elFindByIds, elFlushSequencerWrites, elIndexExists, elRawBulk, elRawSearch } from '../engine';
import { buildPendingRecords, fireReconcile, initPendingRefs, matchCreatedElement, persistPendingRecords, registerPendingRefsEsOps, withStripSink } from './sequencer-pending-refs';
import type { StrippedRef, StrippedRefInput } from './sequencer-pending-refs';
import { computeApplyLevels, groupIndicesByLevel, runBounded } from './sequencer-apply-levels';
import { deferIntents, fireResubmit, initPendingIntents, matchLandedIntents, pendingIntentsAccepting, registerPendingIntentsEsOps } from './sequencer-pending-intents';
import { DeferredMissingReferenceError } from '../../config/errors';
import { flushSequencerEvents } from '../stream/stream-handler';
import { lockResources } from '../../lock/master-lock';
import { SequencerWriteBuffer, setCurrentWriteBuffer } from './sequencer-write-buffer';
import { SEQUENCER_CONFIG } from './sequencer-config';
import { DeferredLanes } from './sequencer-lanes';
import { sequencerMetrics } from './sequencer-metrics';
import { SequencerQueue } from './sequencer-queue';
import { buildIntent } from './sequencer-intent';
import { sequencerIdentityMap, startIdentityMapInvalidation } from './sequencer-identity-map';
import { buildBatchPlan, canonicalKey, classifyPhase } from './sequencer-batch-plan';
import { setCurrentBatchLock } from './sequencer-batch-lock';
import type { CoalesceGroup } from './sequencer-batch-plan';
import type { IntentKind, SequencerIntent } from './sequencer-intent';
import type { AuthContext, AuthUser } from '../../types/user';

const queue = new SequencerQueue();
let loopStarted = false;
let loopDead = false;
let deferSamples = 0; // P2 diagnosis: bounded defer-refusal sampling
let strippedSamples = 0; // s9.10.2: bounded dead-soft-strip sampling
let missingInBatchSamples = 0; // written-index probe: bounded sampling of refs produced in the batch
// s9.9: batches a group may be skipped for a failed in-batch producer before it applies
// through today's path anyway
const FAILED_PRODUCER_DEFER_LIMIT = 2;

export const isSequencerLoopAlive = () => loopStarted && !loopDead;

// storeLoadByIdsWithRefs lives in middleware.ts, which imports this module: the loader is
// registered by middleware at module init instead of imported (no cycle).
type WithRefsLoader = (context: AuthContext, user: AuthUser, ids: string[]) => Promise<any[]>;
type DedupLoader = (context: AuthContext, input: Record<string, any>, inputIds: string[]) => Promise<any[]>;
let withRefsLoader: WithRefsLoader | null = null;
let dedupLoader: DedupLoader | null = null;
export const registerSequencerLoaders = (loaders: { storeLoadByIdsWithRefs: WithRefsLoader; searchExistingRelations?: DedupLoader }) => {
  withRefsLoader = loaders.storeLoadByIdsWithRefs;
  dedupLoader = loaders.searchExistingRelations ?? null;
};

// s10.3 rung 1: relation-dedup prefetch. At pre-resolve, every relation intent whose
// endpoints are already resolvable runs its dedup query CONCURRENTLY (the same filters as
// getExistingRelations, through the registered loader); a relation whose endpoint is
// known-absent at batch start cannot have a pre-existing duplicate, so it is served [] with
// no query at all. Apply-time getExistingRelations consumes the entry through
// takeSequencerDedupPrefetch and only trusts it if its own input ids are a subset of the
// prefetched ones (rename-at-resolution safety). Cleared at every batch boundary.
const dedupPrefetch = new Map<string, { inputIds: Set<string>; existing: any[] }>();
const DEDUP_PREFETCH_CONCURRENCY = 8;

export const sequencerDedupPrefetchKey = (fromInternalId: string, toInternalId: string, input: Record<string, any>, createdByInternalId?: string | null): string => {
  const dates = ['start_time', 'stop_time', 'first_seen', 'last_seen'].map((k) => String(input[k] ?? '')).join('|');
  // createdBy discriminates the dedup query ONLY when the deduplication config is
  // created_by_based for this relation type (default false). Including it
  // unconditionally broke almost every prefetch consumption: the creator identity is
  // typically created IN the same batch, unresolvable at pre-resolve (raw id in the
  // key) but resolved at apply (internal id in the key). Measured on rung1/rung1.1:
  // 8.8k served of 40k prefetched, unchanged by the id-subset fix (s10.3.2).
  const dedupConfig = conf.get('relations_deduplication') ?? { created_by_based: false, types_overrides: {} };
  const config = dedupConfig.types_overrides?.[input.relationship_type] ?? dedupConfig;
  const createdByPart = config.created_by_based ? (createdByInternalId ?? '') : '';
  return `${fromInternalId}|${toInternalId}|${input.relationship_type}|${dates}|${createdByPart}`;
};

export const takeSequencerDedupPrefetch = (key: string, applyInputIds: string[]): any[] | null => {
  const entry = dedupPrefetch.get(key);
  if (!entry) {
    // s10.3.2 diagnosis: distinguish a key miss from a subset rejection
    if (dedupPrefetch.size > 0) sequencerMetrics.searchCaller('relation_dedup_miss_key');
    return null;
  }
  if (!applyInputIds.every((id) => entry.inputIds.has(id))) {
    sequencerMetrics.searchCaller('relation_dedup_miss_subset');
    return null;
  }
  return entry.existing;
};

// s10.3: nested meta objects (external references, kill chain phases, labels) are
// auto-created INSIDE the parent's apply; their ids are derivable from the raw input, so
// probing them at pre-resolve feeds the map (present -> the nested existence check is
// served positive) or the negative cache (absent -> the guaranteed-negative ES search is
// skipped). Measured before this existed: finder_meta = 86,981 searches/run, the single
// largest channel (plan 0010 step 1).
const deriveNestedMetaIds = (input: Record<string, any>): { type: string; id: string }[] => {
  const out: { type: string; id: string }[] = [];
  const labels = input[INPUT_LABELS];
  if (Array.isArray(labels)) {
    labels.forEach((label: any) => {
      if (typeof label === 'string') out.push({ type: ENTITY_TYPE_LABEL, id: idLabel(label) });
    });
  }
  const derive = (entries: any, type: string) => {
    if (!Array.isArray(entries)) return;
    entries.forEach((entry: any) => {
      try {
        if (typeof entry === 'string') out.push({ type, id: entry });
        else if (entry && typeof entry === 'object') out.push({ type, id: generateStandardId(type, entry) });
      } catch {
        // underspecified nested input: it will fail identically at apply, nothing to probe
      }
    });
  };
  derive(input[INPUT_EXTERNAL_REFS], ENTITY_TYPE_EXTERNAL_REFERENCE);
  derive(input[INPUT_KILLCHAIN], ENTITY_TYPE_KILL_CHAIN_PHASE);
  return out;
};

// C2 pre-resolution: two steps, both as SYSTEM_USER under a sequencer-owned context.
const collectBatchResolveIds = (batch: SequencerIntent[]) => {
  const typedIds = new Map<string, Set<string>>();
  const untypedIds = new Set<string>();
  const entityCandidateIds = new Set<string>();
  const addTyped = (type: string, id: string) => {
    let group = typedIds.get(type);
    if (!group) {
      group = new Set<string>();
      typedIds.set(type, group);
    }
    group.add(id);
  };
  batch.forEach((intent) => {
    if (intent.kind === 'entity') {
      intent.candidateIds.forEach((id) => {
        addTyped(intent.type, id);
        entityCandidateIds.add(id);
      });
    } else {
      intent.candidateIds.forEach((id) => untypedIds.add(id));
    }
    intent.referencedIds.forEach((id) => untypedIds.add(id));
    deriveNestedMetaIds(intent.input).forEach(({ type, id }) => addTyped(type, id));
  });
  return { typedIds, untypedIds, entityCandidateIds };
};

// Rung 5 increment 1 (resolve-ahead): warm the identity map for a set of intents grabbed
// from the queue while the CURRENT batch awaits its commit bulk. WARM-UP ONLY: no absence
// marking and no dedup prefetch (both are per-batch state, wiped by the running batch's
// end-of-batch clears), and any entry made stale by the running batch is removed right
// after by its evict(writtenIds). Reads happen pre-refresh: an entity the running batch
// is creating resolves as a miss here and simply re-resolves next cycle (defer path).
const warmResolveAhead = async (batch: SequencerIntent[]) => {
  const t0 = Date.now();
  const context = executionContext('sequencer', SYSTEM_USER);
  const { typedIds, untypedIds, entityCandidateIds } = collectBatchResolveIds(batch);
  const typedMisses: string[] = [];
  const typedTypes = new Set<string>();
  typedIds.forEach((ids, type) => {
    ids.forEach((id) => {
      if (!sequencerIdentityMap.hasBare(id)) {
        typedMisses.push(id);
        typedTypes.add(type);
      }
    });
  });
  if (typedMisses.length > 0) {
    const hits = await elFindByIds(context, SYSTEM_USER, typedMisses, { type: Array.from(typedTypes), searchCaller: 'sequencer_resolve_ahead' }) as any[];
    sequencerIdentityMap.ingestBare(hits);
    sequencerMetrics.esOp('search');
  }
  const untypedMisses = Array.from(untypedIds).filter((id) => !sequencerIdentityMap.hasBare(id));
  if (untypedMisses.length > 0) {
    const hits = await elFindByIds(context, SYSTEM_USER, untypedMisses, { searchCaller: 'sequencer_resolve_ahead' }) as any[];
    sequencerIdentityMap.ingestBare(hits);
    sequencerMetrics.esOp('search');
  }
  if (withRefsLoader) {
    const targetIds = new Set<string>();
    entityCandidateIds.forEach((id) => {
      if (sequencerIdentityMap.hasBare(id)) targetIds.add(id);
    });
    if (targetIds.size > 0) {
      const loaded = await withRefsLoader(context, SYSTEM_USER, Array.from(targetIds));
      loaded.forEach((element) => sequencerIdentityMap.ingestWithRefs(element));
      sequencerMetrics.esOp('search', 3);
    }
  }
  sequencerMetrics.phase('resolve_ahead', (Date.now() - t0) / 1000);
};

const preResolveBatch = async (batch: SequencerIntent[]) => {
  const t0 = Date.now();
  const context = executionContext('sequencer', SYSTEM_USER);
  // s10.3: the negative cache and the dedup prefetch are strictly per-batch state
  sequencerIdentityMap.clearAbsent();
  dedupPrefetch.clear();
  const { typedIds, untypedIds, entityCandidateIds } = collectBatchResolveIds(batch);
  const typedMisses: string[] = [];
  const typedTypes = new Set<string>();
  typedIds.forEach((ids, type) => {
    ids.forEach((id) => {
      if (!sequencerIdentityMap.hasBare(id)) {
        typedMisses.push(id);
        typedTypes.add(type);
      }
    });
  });
  const untypedMisses = Array.from(untypedIds).filter((id) => !sequencerIdentityMap.hasBare(id));
  if (typedMisses.length > 0) {
    const hits = await elFindByIds(context, SYSTEM_USER, typedMisses, { type: Array.from(typedTypes), searchCaller: 'sequencer_preresolve' }) as any[];
    sequencerIdentityMap.ingestBare(hits);
    sequencerMetrics.esOp('search');
    // s10.3: probed under the type union and not found = known absent for any query whose
    // type filter is a subset of that union (see sequencer-identity-map)
    sequencerIdentityMap.markAbsent(typedMisses.filter((id) => !sequencerIdentityMap.hasBare(id)), Array.from(typedTypes));
  }
  if (untypedMisses.length > 0) {
    const hits = await elFindByIds(context, SYSTEM_USER, untypedMisses, { searchCaller: 'sequencer_preresolve' }) as any[];
    sequencerIdentityMap.ingestBare(hits);
    sequencerMetrics.esOp('search');
    // probed with no type filter = unconditionally absent
    sequencerIdentityMap.markAbsent(untypedMisses.filter((id) => !sequencerIdentityMap.hasBare(id)), null);
  }
  // step 2: upsert targets = entity candidate ids now resolved; load their diff basis once
  if (withRefsLoader) {
    const targetIds = new Set<string>();
    entityCandidateIds.forEach((id) => {
      if (sequencerIdentityMap.hasBare(id)) targetIds.add(id);
    });
    if (targetIds.size > 0) {
      const loaded = await withRefsLoader(context, SYSTEM_USER, Array.from(targetIds));
      loaded.forEach((element) => sequencerIdentityMap.ingestWithRefs(element));
      sequencerMetrics.esOp('search', 3); // element + meta rels + their targets
    }
  }
  // step 3 (s10.3 rung 1): dedup prefetch for the batch's relation intents (see header note)
  if (dedupLoader) {
    const jobs: { key: string; inputIds: string[]; run: () => Promise<any[]> }[] = [];
    batch.forEach((intent) => {
      if (intent.kind !== 'relation') return;
      const { fromId, toId, createdBy } = intent.input;
      if (typeof fromId !== 'string' || typeof toId !== 'string') return;
      const fromElement = sequencerIdentityMap.peekBare(fromId);
      const toElement = sequencerIdentityMap.peekBare(toId);
      const createdByKey = typeof createdBy === 'string'
        ? (sequencerIdentityMap.resolveInternalId(createdBy) ?? createdBy)
        : (createdBy?.internal_id ?? null);
      const key = sequencerDedupPrefetchKey(
        fromElement?.internal_id ?? fromId,
        toElement?.internal_id ?? toId,
        intent.input,
        createdByKey,
      );
      if (dedupPrefetch.has(key)) return;
      const endpointAbsent = (!fromElement && sequencerIdentityMap.isKnownAbsent(fromId, null))
        || (!toElement && sequencerIdentityMap.isKnownAbsent(toId, null));
      if (endpointAbsent) {
        // an endpoint absent at batch start cannot carry a pre-existing duplicate
        dedupPrefetch.set(key, { inputIds: new Set(intent.candidateIds), existing: [] });
        return;
      }
      if (!fromElement || !toElement) return; // endpoint not resolved yet: live query at apply
      // entity_type is REQUIRED: without it getInputIds throws in generateAliasesId and the
      // catch below silently keeps candidateIds, defeating the whole union (s10.3.3 diagnosis:
      // 50/50 sampled subset rejections were missing ONLY the regenerated relationship
      // standard id). Same trap as the entity intake candidateIds (see middleware.ts).
      const dedupInput = { ...intent.input, entity_type: intent.input.relationship_type, from: fromElement, to: toElement };
      // s10.3.1: the apply-time ids include the POST-RESOLUTION standard id, which the
      // plan-time candidateIds do not carry. With endpoints resolved it is computable
      // here with the SAME function apply uses; without it the subset check rejected
      // almost every prefetch (measured on rung1-a: 8,830 served of 40,409 prefetched).
      let inputIds = intent.candidateIds;
      try {
        inputIds = Array.from(new Set([...intent.candidateIds, ...getInputIds(intent.input.relationship_type, dedupInput, false)]));
      } catch {
        // underspecified input: keep candidateIds; the subset check will fall back live
      }
      jobs.push({ key, inputIds, run: () => (dedupLoader as DedupLoader)(context, dedupInput, inputIds) });
    });
    for (let i = 0; i < jobs.length; i += DEDUP_PREFETCH_CONCURRENCY) {
      const slice = jobs.slice(i, i + DEDUP_PREFETCH_CONCURRENCY);
      const results = await Promise.all(slice.map(async (job) => {
        try {
          return await job.run();
        } catch {
          return null; // prefetch is an optimization: the live query at apply remains
        }
      }));
      results.forEach((existing, j) => {
        if (existing) dedupPrefetch.set(slice[j].key, { inputIds: new Set(slice[j].inputIds), existing });
      });
    }
  }
  sequencerMetrics.phase('resolve', (Date.now() - t0) / 1000);
};

// D4: one lock set per batch, mirroring every direct-path acquisition: input ids, stored
// instance ids of the resolved upsert targets, impacted relationship endpoints. New standard
// ids on rename are the unpredictable rest: the nested lock site real-locks them.
const batchLockKeys = (groups: CoalesceGroup[]): string[] => {
  const keys = new Set<string>();
  groups.forEach(({ leader }) => {
    leader.candidateIds.forEach((id) => {
      keys.add(id);
      const element = sequencerIdentityMap.peekBare(id);
      if (element) getInstanceIds(element).forEach((k: string) => keys.add(k));
    });
    if (leader.kind === 'relation') {
      [leader.input.fromId, leader.input.toId].forEach((id) => {
        if (typeof id === 'string' && id.length > 0) {
          const internalId = sequencerIdentityMap.resolveInternalId(id);
          keys.add(internalId ?? id);
        }
      });
    }
  });
  return Array.from(keys);
};

interface ParkedIntent {
  intent: SequencerIntent;
  deadline: number;
  parkedAt: number;
}

// Stage E: a successful apply is only PENDING until the batch's writes are flushed and
// refreshed: its promise resolves (and its outcome counts as applied/coalesced) at commit,
// so workers act strictly after ES visibility. Apply-time exceptions still reject immediately.
interface PendingResolution {
  leader: SequencerIntent;
  absorbed: SequencerIntent[];
  result: any;
}

const applyGroup = async (
  group: CoalesceGroup,
  writtenIds: string[],
  pendings: PendingResolution[],
  strippedInputs: StrippedRefInput[],
  onFailure: (group: CoalesceGroup, err: unknown) => void,
  recordPhase = true,
): Promise<boolean> => {
  const { leader, absorbed } = group;
  const t0 = Date.now();
  let success = true;
  // s9.12.3 strip-and-reconcile: the per-apply sink travels with the apply's async context
  // (AsyncLocalStorage), so concurrent applies of one batch each collect their own strips.
  // Strips from nested re-entrant creates land in the same sink and get attributed to the
  // leader element (documented POC approximation).
  const stripSink: StrippedRef[] = [];
  try {
    const result = await withStripSink(stripSink, () => leader.apply());
    const element = result?.element ?? result;
    if (element?.internal_id) {
      // read-your-writes for later intents of THIS batch (E2); evicted at commit (D4a).
      // P2 chaining (s9.7): when a with-refs basis already existed (the element predates
      // the batch, so this apply was an upsert whose result merges attributes and refs),
      // the result REPLACES the basis: the next chain step diffs against it instead of the
      // stale stored element. A creation result is never a valid basis (buildEntityData
      // strips the ref input fields): bare ingest only.
      sequencerIdentityMap.ingestWritten(element, sequencerIdentityMap.hasWithRefs(element.internal_id));
      getInstanceIds(element).forEach((id: string) => writtenIds.push(id));
      // s9.12.3 strip-and-reconcile: refs stripped during THIS apply (pushed into the
      // sink by inputResolveRefs) become pending-ref inputs, persisted with the batch at
      // flush time so the debt commits with the accepted write.
      stripSink.forEach((s) => strippedInputs.push({
        ownerId: element.internal_id,
        ownerType: element.entity_type,
        relType: s.relType,
        targetRef: s.targetRef,
        userId: leader.user.id,
        user: leader.user,
      }));
      // Verdict 31 fix: plan-time member-dead strips (s9.10.2) feed the SAME pending
      // store. The member was declared dead on a bounded wait, but a late member DOES
      // land (proven: this was the dominant estate loss family), and the commit-time
      // match or the sweeper then restores the edge. Input key -> databaseName through
      // the schema; an unmapped key is logged, never silently dropped.
      [leader, ...absorbed].forEach((intent) => {
        (intent.deadStrippedRefs ?? []).forEach(({ inputKey, refId }) => {
          const ref = schemaRelationsRefDefinition.getRelationRef(element.entity_type, inputKey);
          if (ref?.databaseName) {
            strippedInputs.push({
              ownerId: element.internal_id,
              ownerType: element.entity_type,
              relType: ref.databaseName,
              targetRef: refId,
              userId: intent.user.id,
              user: intent.user,
            });
          } else {
            logApp.warn('[SEQUENCER] dead-stripped ref without relation mapping, not recorded', {
              type: element.entity_type, inputKey, refId,
            });
          }
        });
        intent.deadStrippedRefs = undefined;
      });
    }
    pendings.push({ leader, absorbed, result });
  } catch (err) {
    success = false;
    onFailure(group, err);
  }
  if (recordPhase) sequencerMetrics.phase('apply', (Date.now() - t0) / 1000);
  return success;
};

const runBatchLoop = async () => {
  await startIdentityMapInvalidation();
  if (SEQUENCER_CONFIG.stripReconcile) {
    registerPendingRefsEsOps({
      indexExists: (index) => elIndexExists(index),
      createIndex: (index, mappingProperties) => elCreateIndex(index, mappingProperties),
      bulk: async (body) => {
        const esContext = executionContext('sequencer', SYSTEM_USER);
        return elRawBulk(esContext, { body });
      },
      search: async (query) => {
        const esContext = executionContext('sequencer', SYSTEM_USER);
        return elRawSearch(esContext, SYSTEM_USER, null, query);
      },
    });
    await initPendingRefs();
  }
  // retry-gap option 1: hard-ref retention store (used by intents whose context asks for it,
  // today the chunk intake manager's)
  registerPendingIntentsEsOps({
    indexExists: (index) => elIndexExists(index),
    createIndex: (index, mappingProperties) => elCreateIndex(index, mappingProperties),
    bulk: async (body) => {
      const esContext = executionContext('sequencer', SYSTEM_USER);
      return elRawBulk(esContext, { body });
    },
    search: async (query) => {
      const esContext = executionContext('sequencer', SYSTEM_USER);
      return elRawSearch(esContext, SYSTEM_USER, null, query);
    },
  });
  await initPendingIntents();
  logApp.info('[SEQUENCER] batch loop started');
  // Deferral lanes, RESIDUAL since P2 merge-fold (plan 0009 s9.7): same-target different-input
  // ENTITY writes now chain within one batch (each step diffing against the predecessor's
  // in-memory result), so the lanes only carry the non-foldable rest: relations, writes on a
  // same-batch creation, enforced-reference commits, replay contexts, forceDirect companions.
  // Lane form kept from the batchEwp-a diagnosis (2026-08-25): per-canonical-target FIFO,
  // at most ONE per target re-admitted per batch, so a backlog never recycles through
  // pre-resolve + plan every cycle.
  // B10 (2026-09-16): lanes with event-driven wake-up, see sequencer-lanes.ts. A deferral
  // that waits on a queued (or deferred) producer takes no batch slot until the producer
  // settles; re-admissions are capped per cycle and the queue always keeps its share.
  const lanes = new DeferredLanes();
  queue.setExternalLoad(() => ({ count: lanes.size(), bytes: lanes.sizeBytes() }));
  const deferToLane = (intent: SequencerIntent, waitingOn?: string[]) => {
    const laneKey = canonicalKey(intent, (id) => sequencerIdentityMap.resolveInternalId(id));
    lanes.defer(laneKey, intent, waitingOn);
  };
  const laneAdmitCap = Math.max(1, Math.floor(SEQUENCER_CONFIG.maxBatchSize * SEQUENCER_CONFIG.deferredReadmitRatio));
  const settledIds = (intents: SequencerIntent[]): string[] => intents.flatMap((i) => i.candidateIds);
  let parked: ParkedIntent[] = [];
  let rootFailureSamples = 0; // s9.9.3 bounded root-attribution sampling
  // resolve-ahead: intents grabbed from the queue during the previous batch's commit,
  // their identity-map entries already warmed; they enter this cycle's batch first-class
  let carried: SequencerIntent[] = [];
  for (;;) {
    // 1. assemble: one deferred intent per target lane first; when nothing at all is
    // pending, wait for an arrival or the nearest parking deadline (never re-plan a pure
    // parked set in a tight loop); then the parked intents (they re-plan each cycle) and a
    // drain of the queue.
    const batch: SequencerIntent[] = [];
    const admission = lanes.admit(laneAdmitCap);
    admission.intents.forEach((intent) => batch.push(intent));
    const exhaustedIds = new Set(admission.exhausted.map((i) => i.id));
    if (admission.intents.length > 0) queue.notifySlot();
    carried.forEach((intent) => batch.push(intent));
    carried = [];
    if (batch.length === 0 && queue.size() === 0) {
      const nearestDeadline = parked.length > 0
        ? Math.min(...parked.map((p) => p.deadline)) : null;
      const first = nearestDeadline === null
        ? await queue.take()
        : await queue.takeWithTimeout(nearestDeadline - Date.now());
      if (first) {
        sequencerMetrics.queueWait((Date.now() - first.arrivedAt) / 1000);
        batch.push(first);
      }
    }
    const parkedInBatch = parked;
    parked = [];
    parkedInBatch.forEach((p) => batch.push(p.intent));
    // Gather window (§2.6): when service rate ~ arrival rate the self-clocking fixed point
    // collapses to ~1-intent batches (batchD-b measured mean 1.3), which voids coalescing,
    // in-batch ordering and pre-resolution amortization. A bounded wait before the drain
    // re-forms real batches. Skipped when the queue already fills the batch: saturation
    // keeps pure self-clocking with no added latency.
    if (SEQUENCER_CONFIG.gatherWindowMs > 0
      && batch.length + queue.size() < SEQUENCER_CONFIG.maxBatchSize) {
      await new Promise<void>((resolve) => {
        setTimeout(resolve, SEQUENCER_CONFIG.gatherWindowMs);
      });
    }
    // B10: whatever the lanes and the parked set assembled, the queue gets at least its
    // share of the cap every cycle (a batch may exceed the cap by that share): the queued
    // producers the waiters depend on are always reached
    const drainTarget = Math.max(SEQUENCER_CONFIG.maxBatchSize, batch.length + laneAdmitCap);
    while (batch.length < drainTarget) {
      const next = queue.tryPop();
      if (!next) break;
      // queue wait is recorded on FIRST entry into a batch only (deferred and parked
      // re-entries would recount and dominate the histogram)
      sequencerMetrics.queueWait((Date.now() - next.arrivedAt) / 1000);
      batch.push(next);
    }
    if (batch.length === 0) continue;
    sequencerMetrics.queueDepth(queue.size());
    // 2. pre-resolve (optimization: on failure the batch still applies through ES)
    try {
      await preResolveBatch(batch);
    } catch (err) {
      logApp.error('[SEQUENCER] batch pre-resolution failed, applying without it', { cause: err });
    }
    // 3. plan: phases, dependency order, parking, coalescing
    const now = Date.now();
    const parkedMeta = new Map(parkedInBatch.map((p) => [p.intent.id, p]));
    const forceDirect = new Set<string>();
    parkedInBatch.forEach((p) => {
      if (p.deadline <= now) forceDirect.add(p.intent.id);
    });
    exhaustedIds.forEach((id) => forceDirect.add(id)); // B10: waited too long, apply as-is
    // retry-gap option 1: creations to RETAIN (pending intents) instead of rejecting, settled
    // after the apply phase, once persisted (a chunk ack must never outrun the recorded debt)
    const deferrals: { intent: SequencerIntent; absorbed: SequencerIntent[]; missing: string[]; err: unknown }[] = [];
    const hardRefIds = (intent: SequencerIntent): string[] => [intent.input.fromId, intent.input.toId]
      .filter((id): id is string => typeof id === 'string' && id.length > 0);
    const writtenIds: string[] = [];
    // written-index probe (2026-09-21): where does a reference missing at apply come from?
    // written_*: this batch already applied its producer (in_map: the map still holds it, so
    // the resolver never asked the map; evicted: a mid-batch invalidation dropped it);
    // in_batch: the producer is co-batched but not applied yet, or failed; outside: not in
    // this batch at all. Says whether a batch-local written index has anything to close.
    let batchOwnIds: Set<string> | null = null;
    const classifyMissing = (missing: string[], outcome: 'parked' | 'deferred' | 'failed' | 'final') => {
      const own = batchOwnIds ?? new Set<string>(plan.order.flatMap((g) => [g.leader, ...g.absorbed].flatMap((i) => i.candidateIds)));
      batchOwnIds = own;
      const written = new Set(writtenIds);
      missing.forEach((id) => {
        let origin = 'outside';
        if (written.has(id)) origin = sequencerIdentityMap.peekBare(id) ? 'written_in_map' : 'written_evicted';
        else if (own.has(id)) origin = 'in_batch';
        sequencerMetrics.missingRefOrigin(origin, outcome);
        if (origin !== 'outside' && missingInBatchSamples < 20) {
          missingInBatchSamples += 1;
          logApp.info('[SEQUENCER] missing reference produced in this batch', { id, origin, outcome });
        }
      });
    };
    const t0 = Date.now();
    const plan = buildBatchPlan(batch, (id) => sequencerIdentityMap.resolveInternalId(id), forceDirect, {
      parkSoftRefs: SEQUENCER_CONFIG.parkSoftRefs,
      memberWaitLimit: SEQUENCER_CONFIG.memberWaitLimit,
      queueHas: (id) => queue.hasCandidate(id) || lanes.hasResident(id), // s9.8.3 queue index + B10 lane residents
    });
    sequencerMetrics.phase('order', (Date.now() - t0) / 1000);
    if (plan.chainedSteps > 0) sequencerMetrics.chainSteps(plan.chainedSteps);
    // s9.12.1 relatedness instrumentation: in-batch dependsOn edges (dependents co-batched
    // with their producers) and distinct sources (bundle proxy at prefetch=1) per batch.
    const inBatchEdges = plan.order.reduce((n, g) => n + (g.dependsOn?.length ?? 0), 0);
    const distinctSources = new Set(batch.map((intent) => intent.source)).size;
    sequencerMetrics.batchRelatedness(inBatchEdges, distinctSources);
    // s9.8.2 "member dead": the ref was declared in-bundle and its producer never showed
    // up within the bounded wait: it failed its own creation, no retry can help. Reject
    // NOW with the FINAL error code (distinct from MISSING_REFERENCE_ERROR on purpose):
    // pycti's retry classifier reports the object once and drops it, no retry budget burnt.
    plan.finalMissing.forEach(({ intent, missing }) => {
      classifyMissing(missing, 'final');
      sequencerMetrics.memberDead();
      const err = MissingReferenceFinalError({ unresolvedIds: missing, doc_code: 'ELEMENT_NOT_FOUND' });
      // retry-gap option 1: a "dead" member is usually just LATE (verdict 31): retain the
      // creation when the caller asked for it, it lands when the member does or expires visibly
      if (intent.context?.deferMissingRefs && pendingIntentsAccepting()) {
        deferrals.push({ intent, absorbed: [], missing, err });
        return;
      }
      sequencerMetrics.intent('failed', intent.kind);
      intent.reject(err);
      lanes.wake(intent.candidateIds, 'failed');
    });
    // s9.10.2: dead SOFT member refs were stripped in the plan; the intents apply without
    // them. Counted per stripped id; first occurrences sampled for live diagnosis.
    plan.strippedDead.forEach(({ intent, stripped }) => {
      sequencerMetrics.memberDeadStripped(stripped.length);
      if (strippedSamples < 20) {
        strippedSamples += 1;
        logApp.info('[SEQUENCER] dead member refs stripped', {
          type: intent.type,
          kind: intent.kind,
          stripped: stripped.slice(0, 5),
        });
      }
    });
    plan.deferred.forEach(({ intent, reason, waitingOn }) => {
      deferToLane(intent, waitingOn);
      sequencerMetrics.intent('deferred', intent.kind);
      sequencerMetrics.deferReason(reason);
      // P2 diagnosis: sample the first refusals with every predicate clause, so a live run
      // tells WHY chains are refused without guesswork
      if (deferSamples < 20) {
        deferSamples += 1;
        logApp.info('[SEQUENCER] defer sample', {
          reason,
          type: intent.type,
          candidates: intent.candidateIds.slice(0, 3),
          resolved: intent.candidateIds.slice(0, 3).map((id) => sequencerIdentityMap.resolveInternalId(id) !== null),
          refsOpts: intent.opts?.references?.length ?? 0,
          eventId: intent.context?.eventId ?? null,
          syncUpsert: intent.context?.synchronizedUpsert ?? false,
        });
      }
    });
    plan.parked.forEach(({ intent }) => {
      const known = parkedMeta.get(intent.id);
      if (known) {
        parked.push(known); // keeps the original deadline
      } else {
        // v3.1: deadline anchored at PARK time (anchoring at arrivedAt pre-consumed the
        // window for intents that lived in lanes or retries first: 95% expired in ~0.35 s)
        sequencerMetrics.intent('parked', intent.kind);
        parked.push({ intent, deadline: now + SEQUENCER_CONFIG.parkDeadlineMs, parkedAt: now });
      }
    });
    parkedMeta.forEach((p) => {
      if (forceDirect.has(p.intent.id)) {
        sequencerMetrics.intent('expired', p.intent.kind);
        sequencerMetrics.parked((now - p.parkedAt) / 1000);
      } else if (!parked.find((x) => x.intent.id === p.intent.id)) {
        // unparked: its reference resolved in this batch
        sequencerMetrics.parked((now - p.parkedAt) / 1000);
      }
    });
    if (plan.order.length === 0) {
      sequencerMetrics.batchCommitted(0);
      continue;
    }
    // 4. one batch lock over the predicted key set
    const lockKeys = batchLockKeys(plan.order);
    let lock;
    try {
      lock = await lockResources(lockKeys, {});
    } catch (err) {
      plan.order.forEach(({ leader, absorbed }) => {
        sequencerMetrics.intent('failed', leader.kind);
        leader.reject(err);
        absorbed.forEach((a) => {
          sequencerMetrics.intent('failed', a.kind);
          a.reject(err);
        });
      });
      continue;
    }
    setCurrentBatchLock({ heldKeys: new Set(lockKeys), signal: lock.signal });
    // 5. apply leaders one at a time (C6) with the Stage E write buffer armed, then commit:
    // flush the buffered writes (one docs bulk + one side/update bulk + ONE refresh), push the
    // buffered events in application order, and only then resolve the intents' promises.
    // v3.1 apply-failure policy: a MISSING_REFERENCE_ERROR (thrown by inputResolveRefs
    // BEFORE any write) on a non-expired intent re-parks it instead of rejecting: the
    // reference is usually in flight, and the plan-time predicate cannot see every
    // plan->apply coherence gap. Anything else, or an exhausted deadline, rejects as today.
    const onApplyFailure = (group: CoalesceGroup, err: unknown) => {
      const { leader, absorbed } = group;
      const isMissingRef = (err as any)?.extensions?.code === 'MISSING_REFERENCE_ERROR';
      const missingIds = (): string[] => {
        const unresolved: unknown = (err as any)?.extensions?.data?.unresolvedIds ?? (err as any)?.data?.unresolvedIds;
        return Array.isArray(unresolved) && unresolved.length > 0 ? unresolved.map(String) : hardRefIds(leader);
      };
      const known = parkedMeta.get(leader.id);
      const deadline = known?.deadline ?? (Date.now() + SEQUENCER_CONFIG.parkDeadlineMs);
      if (SEQUENCER_CONFIG.parkSoftRefs && isMissingRef && !forceDirect.has(leader.id) && deadline > Date.now()) {
        classifyMissing(missingIds(), 'parked');
        const parkedAt = known?.parkedAt ?? Date.now();
        sequencerMetrics.intent('parked', leader.kind);
        parked.push({ intent: leader, deadline, parkedAt });
        absorbed.forEach((a) => {
          sequencerMetrics.intent('parked', a.kind);
          parked.push({ intent: a, deadline, parkedAt });
        });
        return;
      }
      // retry-gap option 1: past its deadline, a creation still missing a hard reference is
      // RETAINED (pending intents store) when the caller asked for it, instead of failing
      // into a retry ladder that no longer exists on the chunk path
      if (isMissingRef && leader.context?.deferMissingRefs && pendingIntentsAccepting()) {
        const missing = missingIds();
        classifyMissing(missing, 'deferred');
        deferrals.push({ intent: leader, absorbed, missing, err });
        return;
      }
      if (isMissingRef) classifyMissing(missingIds(), 'failed');
      sequencerMetrics.intent('failed', leader.kind);
      leader.reject(err);
      // absorbed asserted the same input on the same target: they fail identically today
      absorbed.forEach((a) => {
        sequencerMetrics.intent('failed', a.kind);
        a.reject(err);
      });
      lanes.wake(settledIds([leader, ...absorbed]), 'failed'); // B10: waiters re-plan
    };
    const strippedInputs: StrippedRefInput[] = [];
    const buffer = new SequencerWriteBuffer();
    const pendings: PendingResolution[] = [];
    let aheadGrab: Promise<SequencerIntent[]> | null = null;
    setCurrentWriteBuffer(buffer);
    try {
      // s9.9 failure-aware execution: a consumer whose in-batch producer failed (or was
      // itself skipped) must NOT apply behind it: it would fail in cascade and burn its
      // worker retry budget (measured on ch16-c: 5.7k cascade retries, estate -1,493).
      // Skipped groups defer one batch (the producer's worker retry usually lands within
      // a cycle), bounded to FAILED_PRODUCER_DEFER_LIMIT; at the limit the group applies
      // through today's path, so degradation is never a new loss class.
      const failedAt: boolean[] = new Array(plan.order.length).fill(false);
      const { applyConcurrency } = SEQUENCER_CONFIG;
      const processGroup = async (i: number) => {
        const group = plan.order[i];
        const failedDep = (group.dependsOn ?? []).some((d) => failedAt[d]);
        if (failedDep && (group.leader.failedProducerDefers ?? 0) < FAILED_PRODUCER_DEFER_LIMIT) {
          group.leader.failedProducerDefers = (group.leader.failedProducerDefers ?? 0) + 1;
          failedAt[i] = true; // transitive: dependents of a skipped group skip too
          [group.leader, ...group.absorbed].forEach((intent) => {
            deferToLane(intent);
            sequencerMetrics.intent('deferred', intent.kind);
            sequencerMetrics.deferReason('failed_producer');
          });
          return;
        }
        // s9.9.3 root attribution: a failure with NO failed in-batch producer is a
        // cascade ROOT: count it by code and sample the first ones
        const onFailure = (g: CoalesceGroup, err: unknown) => {
          if (!failedDep) {
            const code = String((err as any)?.extensions?.code ?? (err as any)?.name ?? 'UNKNOWN');
            sequencerMetrics.rootFailure(code);
            if (rootFailureSamples < 20) {
              rootFailureSamples += 1;
              logApp.info('[SEQUENCER] cascade root failure', {
                code,
                type: g.leader.type,
                kind: g.leader.kind,
                unresolvedIds: (err as any)?.extensions?.data?.unresolvedIds ?? (err as any)?.data?.unresolvedIds ?? null,
              });
            }
          }
          onApplyFailure(g, err);
        };
        const ok = await applyGroup(group, writtenIds, pendings, strippedInputs, onFailure, applyConcurrency <= 1);
        if (!ok) failedAt[i] = true;
      };
      if (applyConcurrency <= 1) {
        // the path measured through the whole study: plan order, one apply at a time
        for (let i = 0; i < plan.order.length; i += 1) await processGroup(i);
      } else {
        // rung 5 (2026-09-21): groups without an in-batch edge between them apply concurrently,
        // level by level (a level's producers are all settled before its consumers start, so
        // the failed-producer skip reads settled state). The writer stays one loop and one
        // commit: only the ES round trips of independent intents overlap, bounded by
        // apply_concurrency. The apply phase is then recorded once per batch (wall time).
        const tApply = Date.now();
        const groupIntents = (i: number) => [plan.order[i].leader, ...plan.order[i].absorbed];
        const ownIdsOf = (i: number) => {
          const ids = new Set<string>();
          groupIntents(i).forEach((it) => {
            const endpoints = it.kind === 'relation' ? new Set([it.input.fromId, it.input.toId]) : new Set();
            it.candidateIds.forEach((id) => {
              if (!endpoints.has(id)) ids.add(id);
            });
          });
          return ids;
        };
        const refIdsOf = (i: number) => {
          const ids = new Set<string>();
          groupIntents(i).forEach((it) => {
            if (it.kind === 'relation') [it.input.fromId, it.input.toId].forEach((id) => {
              if (typeof id === 'string') ids.add(id);
            });
            (it.referencedIds ?? []).forEach((id) => ids.add(id));
          });
          return ids;
        };
        const byLevel = groupIndicesByLevel(computeApplyLevels(plan.order, {
          phaseOf: (i) => classifyPhase(plan.order[i].leader), ownIdsOf, refIdsOf,
        }));
        for (let lvl = 0; lvl < byLevel.length; lvl += 1) {
          const indices = byLevel[lvl] ?? [];
          if (indices.length > 0) await runBounded(indices, applyConcurrency, (i) => processGroup(i));
        }
        sequencerMetrics.applyLevels(byLevel.length);
        sequencerMetrics.phase('apply', (Date.now() - tApply) / 1000);
      }
      setCurrentWriteBuffer(null); // flush must not re-buffer
      // resolve-ahead: while the commit bulk awaits ES, grab the queued intents of the
      // NEXT batch and warm their identity-map entries. The grab happens now (post-apply)
      // so nothing mutates the lanes; the warm's staleness is neutralized by this batch's
      // evict(writtenIds)/clearAbsent in the finally, which runs AFTER the await below.
      if (SEQUENCER_CONFIG.resolveAhead) {
        aheadGrab = (async () => {
          const grabbed: SequencerIntent[] = [];
          while (grabbed.length < SEQUENCER_CONFIG.maxBatchSize) {
            const next = queue.tryPop();
            if (!next) break;
            sequencerMetrics.queueWait((Date.now() - next.arrivedAt) / 1000);
            grabbed.push(next);
          }
          if (grabbed.length > 0) {
            try {
              await warmResolveAhead(grabbed);
            } catch (err) {
              logApp.error('[SEQUENCER] resolve-ahead warm failed, batch resolves normally', { cause: err });
            }
          }
          return grabbed;
        })();
      }
      try {
        const tFlush = Date.now();
        // retry-gap option 1: persist the retained creations BEFORE their promises settle
        // (the chunk ack must never outrun the recorded debt); a store failure falls back to
        // today's rejection, visibly
        if (deferrals.length > 0) {
          let retained = false;
          try {
            retained = await deferIntents(deferrals.map(({ intent, missing }) => ({ intent, missing })));
          } catch (deferErr) {
            logApp.error('[SEQUENCER] pending intents persistence failed, rejecting as today', { cause: deferErr });
          }
          deferrals.forEach(({ intent, absorbed, missing, err }) => {
            const outcome = retained ? DeferredMissingReferenceError({ unresolvedIds: missing, doc_code: 'ELEMENT_NOT_FOUND' }) : err;
            sequencerMetrics.intent(retained ? 'retained' : 'failed', intent.kind);
            intent.reject(outcome);
            absorbed.forEach((a) => {
              sequencerMetrics.intent(retained ? 'retained' : 'failed', a.kind);
              a.reject(outcome);
            });
            // B10: a retained or failed producer will not land in this run: its waiters re-plan
            lanes.wake(settledIds([intent, ...absorbed]), 'failed');
          });
        }
        if (buffer.indexCalls.length > 0 || buffer.updateOps.length > 0) {
          const flushContext = executionContext('sequencer', SYSTEM_USER);
          await elFlushSequencerWrites(flushContext, SYSTEM_USER, buffer);
        }
        sequencerMetrics.phase('commit', (Date.now() - tFlush) / 1000);
        const tEvents = Date.now();
        await flushSequencerEvents(buffer.events);
        sequencerMetrics.phase('events', (Date.now() - tEvents) / 1000);
        // s9.12.3: persist this batch's strip records BEFORE resolving the intents (the
        // worker ack must never outrun the recorded debt), then match every committed
        // element against the pending population and re-assert the hits (fire-and-forget:
        // the re-assertions re-enter the boundary as normal mutations).
        if (strippedInputs.length > 0) {
          await persistPendingRecords(buildPendingRecords(strippedInputs));
        }
        pendings.forEach(({ result }) => {
          const element = result?.element ?? result;
          const hits = matchCreatedElement(element);
          if (hits.length > 0) fireReconcile(hits);
          // retry-gap option 1: a landed element may be the missing endpoint of retained
          // creations: re-submit them through the boundary (fire-and-forget, sequential)
          const landed = matchLandedIntents(element);
          if (landed.length > 0) fireResubmit(landed);
        });
        pendings.forEach(({ leader, absorbed, result }) => {
          sequencerMetrics.intent('applied', leader.kind);
          leader.resolve(result);
          absorbed.forEach((a) => {
            sequencerMetrics.intent('coalesced', a.kind);
            a.resolve(result);
          });
        });
        // B10: the committed ids wake the deferrals waiting on them (next cycle, in order)
        pendings.forEach(({ leader, absorbed }) => lanes.wake(settledIds([leader, ...absorbed]), 'landed'));
      } catch (err) {
        // E5 v1: batch-level rejection. The workers retry through the full existence-checking
        // path (upsert), so nothing is replayed blindly; the flush already refreshed whatever
        // did land (see elFlushSequencerWrites).
        logApp.error('[SEQUENCER] batch flush failed, rejecting the batch', { cause: err });
        pendings.forEach(({ leader, absorbed }) => {
          sequencerMetrics.intent('failed', leader.kind);
          leader.reject(err);
          absorbed.forEach((a) => {
            sequencerMetrics.intent('failed', a.kind);
            a.reject(err);
          });
          lanes.wake(settledIds([leader, ...absorbed]), 'failed');
        });
      }
    } finally {
      // resolve-ahead intents are recovered FIRST (they were popped off the queue and must
      // never be lost), and BEFORE the evict/clear below so any stale warm entry for an
      // id this batch wrote is wiped right after the warm completed.
      if (aheadGrab) carried = await aheadGrab;
      setCurrentWriteBuffer(null);
      setCurrentBatchLock(null);
      if (writtenIds.length > 0) sequencerIdentityMap.evict(writtenIds, 'write');
      sequencerIdentityMap.clearWritten(); // batch-local: the next batch re-reads its writes from ES
      // s10.3: absence and prefetches are only valid while this batch's lock is held
      sequencerIdentityMap.clearAbsent();
      dedupPrefetch.clear();
      await lock.unlock();
    }
    // record the REAL assembly size (before the batchEwp-a diagnosis this recorded the
    // applied-group count, which hid a 200-intent assembly behind a mean of 2)
    sequencerMetrics.batchCommitted(batch.length);
  }
};

const runPassthroughLoop = async () => {
  logApp.info('[SEQUENCER] pass-through loop started');
  for (;;) {
    const intent = await queue.take();
    sequencerMetrics.queueWait((Date.now() - intent.arrivedAt) / 1000);
    const t0 = Date.now();
    try {
      const result = await intent.apply();
      sequencerMetrics.intent('applied', intent.kind);
      intent.resolve(result);
    } catch (err) {
      sequencerMetrics.intent('failed', intent.kind);
      intent.reject(err);
    }
    sequencerMetrics.phase('apply', (Date.now() - t0) / 1000);
  }
};

const ensureLoop = () => {
  if (loopStarted) return;
  loopStarted = true;
  const runner = SEQUENCER_CONFIG.mode === 'batch' ? runBatchLoop() : runPassthroughLoop();
  runner.catch((err) => {
    // The loop only awaits queue.take() and guarded work: reaching here is a bug. Fail open:
    // every later submit takes the direct path, ingestion continues without the sequencer.
    loopDead = true;
    logApp.error('[SEQUENCER] loop died, failing open to the direct path', { cause: err });
  });
};

interface SubmitArgs {
  kind: IntentKind;
  type: string;
  input: Record<string, any>;
  opts: Record<string, any>;
  candidateIds: string[];
  referencedIds?: string[];
  memberRefIds?: Set<string>;
  apply: () => Promise<any>;
}

// Called by the boundary (middleware.ts) AFTER isSequencerEligible returned true. The apply
// closure wraps the direct implementation with the re-entrancy-marked context.
export const submitIntent = async (context: AuthContext, user: AuthUser, args: SubmitArgs): Promise<any> => {
  if (loopDead) {
    sequencerMetrics.intent('bypassed', args.kind);
    return args.apply();
  }
  ensureLoop();
  const intent = buildIntent({ ...args, user, context });
  await queue.put(intent);
  // the caller's pre-loop phase ends here (chunk intake pacing, see chunkIntakeManager)
  if (typeof context.onIntentQueued === 'function') {
    try {
      context.onIntentQueued();
    } catch (e) {
      logApp.warn('[SEQUENCER] onIntentQueued hook failed', { cause: e });
    }
  }
  return intent.promise;
};
