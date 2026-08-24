// POC ingestion sequencer (plan 0009, Stage B3/B5 + C1/C2/C6). Two modes:
//   - passthrough (Stage B): one intent at a time through the unchanged path, concurrency 1.
//     Measures the sequential floor; no cache, no batching.
//   - batch (Stage C): self-clocking group commit. The loop takes everything queued when it
//     becomes free (round-robin per source, bounded by the caps), PRE-RESOLVES the whole
//     batch's ids in two searches (typed candidates + untyped references) plus one with-refs
//     load for the upsert targets, fills the identity map, then still applies intents ONE AT
//     A TIME (C6: no intra-batch write race). Reads inside the apply path hit the map through
//     context.sequencer.resolutions (wired in elFindByIds / storeLoadByIdsWithRefs).
// Own writes are EVICTED from the map after each apply (D4a): the next batch re-resolves
// fresh. Errors are caught per intent and rejected on its promise: the GraphQL error contract
// is unchanged. Fail-open watchdog: a dead loop sends every later submit direct and logs.
import { logApp } from '../../config/conf';
import { executionContext, SYSTEM_USER } from '../../utils/access';
import { getInstanceIds } from '../../schema/identifier';
import { elFindByIds } from '../engine';
import { SEQUENCER_CONFIG } from './sequencer-config';
import { sequencerMetrics } from './sequencer-metrics';
import { SequencerQueue } from './sequencer-queue';
import { buildIntent } from './sequencer-intent';
import { sequencerIdentityMap, startIdentityMapInvalidation } from './sequencer-identity-map';
import type { IntentKind, SequencerIntent } from './sequencer-intent';
import type { AuthContext, AuthUser } from '../../types/user';

const queue = new SequencerQueue();
let loopStarted = false;
let loopDead = false;

export const isSequencerLoopAlive = () => loopStarted && !loopDead;

// storeLoadByIdsWithRefs lives in middleware.ts, which imports this module: the loader is
// registered by middleware at module init instead of imported (no cycle).
type WithRefsLoader = (context: AuthContext, user: AuthUser, ids: string[]) => Promise<any[]>;
let withRefsLoader: WithRefsLoader | null = null;
export const registerSequencerLoaders = (loaders: { storeLoadByIdsWithRefs: WithRefsLoader }) => {
  withRefsLoader = loaders.storeLoadByIdsWithRefs;
};

// C2 pre-resolution: two steps, both as SYSTEM_USER under a sequencer-owned context.
// Step 1: union of candidate ids (typed by the entity intents' declared types) and referenced
// ids (untyped: ref target families are not tracked per id in v1) -> map lookup -> at most two
// elFindByIds calls for the misses. Step 2: candidate ids that resolved to an existing element
// are the batch's upsert targets; those not cached with refs are loaded once for the whole
// batch with storeLoadByIdsWithRefs (3 searches total instead of 3 per upsert).
const preResolveBatch = async (batch: SequencerIntent[]) => {
  const t0 = Date.now();
  const context = executionContext('sequencer', SYSTEM_USER);
  const typedIds = new Map<string, Set<string>>(); // type -> candidate ids
  const untypedIds = new Set<string>();
  const entityCandidateIds = new Set<string>();
  batch.forEach((intent) => {
    if (intent.kind === 'entity') {
      let group = typedIds.get(intent.type);
      if (!group) {
        group = new Set<string>();
        typedIds.set(intent.type, group);
      }
      intent.candidateIds.forEach((id) => {
        group?.add(id);
        entityCandidateIds.add(id);
      });
    } else {
      intent.candidateIds.forEach((id) => untypedIds.add(id));
    }
    intent.referencedIds.forEach((id) => untypedIds.add(id));
  });
  // map lookup first: only misses go to ES
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
    const hits = await elFindByIds(context, SYSTEM_USER, typedMisses, { type: Array.from(typedTypes) }) as any[];
    sequencerIdentityMap.ingestBare(hits);
    sequencerMetrics.esOp('search');
  }
  if (untypedMisses.length > 0) {
    const hits = await elFindByIds(context, SYSTEM_USER, untypedMisses) as any[];
    sequencerIdentityMap.ingestBare(hits);
    sequencerMetrics.esOp('search');
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
  sequencerMetrics.phase('resolve', (Date.now() - t0) / 1000);
};

const applyIntent = async (intent: SequencerIntent) => {
  const t0 = Date.now();
  try {
    const result = await intent.apply();
    sequencerMetrics.intent('applied', intent.kind);
    // D4a: evict own writes, the next batch re-resolves fresh
    const element = result?.element ?? result;
    if (element?.internal_id) {
      sequencerIdentityMap.evict(getInstanceIds(element), 'write');
    }
    intent.resolve(result);
  } catch (err) {
    sequencerMetrics.intent('failed', intent.kind);
    intent.reject(err);
  }
  sequencerMetrics.phase('apply', (Date.now() - t0) / 1000);
};

const runLoop = async () => {
  if (SEQUENCER_CONFIG.mode === 'batch') {
    await startIdentityMapInvalidation();
    logApp.info('[SEQUENCER] batch loop started');
    for (;;) {
      const batch = await queue.takeBatch(
        SEQUENCER_CONFIG.maxBatchSize,
        SEQUENCER_CONFIG.maxBatchBytes,
        SEQUENCER_CONFIG.gatherWindowMs,
      );
      batch.forEach((intent) => sequencerMetrics.queueWait((Date.now() - intent.arrivedAt) / 1000));
      try {
        await preResolveBatch(batch);
      } catch (err) {
        // pre-resolution is an optimization: on failure the batch still applies through the
        // unchanged path (reads fall back to ES on map misses)
        logApp.error('[SEQUENCER] batch pre-resolution failed, applying without it', { cause: err });
      }
      for (let i = 0; i < batch.length; i += 1) {
        await applyIntent(batch[i]);
      }
      sequencerMetrics.batchCommitted(batch.length);
    }
  } else {
    logApp.info('[SEQUENCER] pass-through loop started');
    for (;;) {
      const intent = await queue.take();
      sequencerMetrics.queueWait((Date.now() - intent.arrivedAt) / 1000);
      await applyIntent(intent);
    }
  }
};

const ensureLoop = () => {
  if (loopStarted) return;
  loopStarted = true;
  runLoop().catch((err) => {
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
  return intent.promise;
};
