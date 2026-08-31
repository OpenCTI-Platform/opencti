// POC ingestion sequencer (plan 0009, Stage D1/D2/D3 + P2 merge-fold s9.7). Pure batch
// planning, no I/O:
//   - phase classification (D1): 0 entities, 1 core relationships/sightings, 2 containers
//     with members and relationships whose endpoint is a relationship;
//   - coalescing (D3): same canonical target AND identical normalized input -> one leader
//     application, absorbed intents share its result;
//   - merge-fold (P2, s9.7): same target with a DIFFERENT input CHAINS behind the previous
//     write when the fold is provably safe (see isFoldable): the steps stay in the batch,
//     ordered by a chain edge, and each step's upsert diffs against the predecessor's
//     in-memory result (the loop re-ingests it with-refs). Non-foldable cases keep the
//     next-batch deferral (residual: relations, same-batch creations, commits, replays);
//   - dependency ordering and parking (D2): an unresolved reference produced by another
//     intent of the batch orders the consumer after its producer (both shapes: relation or
//     container waiting for its endpoint/member, entity referencing a same-batch entity);
//     unresolved with no in-batch producer -> parked (the loop holds it until a later batch
//     resolves it or its deadline passes, then applies it through the unchanged path).
// Cycles are broken by (phase, arrival) order; a parked intent always has a deadline.
import type { SequencerIntent } from './sequencer-intent';

export interface CoalesceGroup {
  leader: SequencerIntent;
  absorbed: SequencerIntent[];
}

// P2 diagnosis: WHY a same-target different-input intent was refused a chain (s9.7.4)
export type DeferReason = 'relation' | 'force_direct' | 'self_not_foldable' | 'head_not_foldable' | 'unresolved_target';

export interface BatchPlan {
  order: CoalesceGroup[];
  deferred: { intent: SequencerIntent; reason: DeferReason }[];
  parked: { intent: SequencerIntent; missing: string[] }[];
  // P2: applications beyond each chain's first step (the volume that left `deferred`)
  chainedSteps: number;
}

export const classifyPhase = (intent: SequencerIntent): number => {
  if (intent.kind === 'entity') {
    const objects = intent.input.objects;
    return Array.isArray(objects) && objects.length > 0 ? 2 : 0;
  }
  const { fromId, toId } = intent.input;
  const endpointIsRelation = [fromId, toId].some((id) => typeof id === 'string'
    && (id.startsWith('relationship--') || id.startsWith('sighting--')));
  return endpointIsRelation ? 2 : 1;
};

const stableStringify = (value: any): string => {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(value[k])}`).join(',')}}`;
};

// Canonical target: the resolved internal id when any candidate id is known, otherwise the
// sorted candidate id set (two intents asserting the same new element share it). For
// ref/internal relationships the standard id is random, identity is (from, to, type).
// Exported: the loop keys its deferred lanes on it (one deferred release per target per batch).
export const canonicalKey = (intent: SequencerIntent, resolveId: (id: string) => string | null): string => {
  if (intent.kind === 'relation') {
    const { fromId, toId } = intent.input;
    const rf = typeof fromId === 'string' ? (resolveId(fromId) ?? fromId) : String(fromId);
    const rt = typeof toId === 'string' ? (resolveId(toId) ?? toId) : String(toId);
    return `r:${intent.type}:${rf}:${rt}`;
  }
  for (let i = 0; i < intent.candidateIds.length; i += 1) {
    const resolved = resolveId(intent.candidateIds[i]);
    if (resolved) return `e:${resolved}`;
  }
  // no candidate id at all: the planner cannot reason about this target's identity, so the
  // intent gets a key of its own (standalone apply, today's semantics). Sharing a key here
  // collapsed EVERY id-less intent onto one fictitious target (found live 2026-08-31: the
  // boundary's candidate ids were empty for all entities, so all of them collided on "e:"
  // and one applied per batch while the rest deferred).
  if (intent.candidateIds.length === 0) return `e:!${intent.id}`;
  return `e:${[...intent.candidateIds].sort().join(',')}`;
};

// D2 v3 (2026-08-25, after the batchEwp series under worker-side concurrency): three
// dependency classes.
//   - HARD deps: a relation's fromId/toId. Unresolved with no producer -> the direct path
//     would throw MissingReferenceError: parking buys the in-window resolution.
//   - SOFT deps: every other referenced id. They ORDER after an in-batch producer (the
//     b2->b1 case) and, since v3, an unresolved one with NO producer also PARKS (5 s
//     deadline): with N messages in flight per queue the serial per-queue ordering is gone,
//     cross-bundle refs arrive before their producers (measured: missing_ref 31-43% vs 5%
//     serial), and the producer is usually already in flight, so an in-platform wait
//     replaces a full worker NACK round trip. On expiry the intent applies through the
//     unchanged path (reject then retry, exactly today's behavior plus the deadline).
//   - AUTO-CREATED families never park (the D2 v1 lesson, 98% of parks expired): labels,
//     external references, kill chain phases and vocabularies are created on the fly by
//     the direct path and never arrive as producer intents; waiting for them is pure
//     added latency.
const AUTO_CREATED_REF_PREFIXES = ['label--', 'external-reference--', 'kill-chain-phase--', 'vocabulary--'];
const isAutoCreatedRef = (id: string): boolean => AUTO_CREATED_REF_PREFIXES.some((prefix) => id.startsWith(prefix));

const hardDependencyIds = (intent: SequencerIntent): string[] => {
  if (intent.kind !== 'relation') return [];
  const own = new Set(intent.candidateIds);
  return [intent.input.fromId, intent.input.toId]
    .filter((id) => typeof id === 'string' && id.length > 0 && !own.has(id));
};

const softDependencyIds = (intent: SequencerIntent): string[] => {
  const own = new Set(intent.candidateIds);
  return intent.referencedIds.filter((id) => typeof id === 'string' && id.length > 0 && !own.has(id));
};

// P2 (plan 0009 s9.7): a same-target intent with a different input chains behind the
// previous write instead of deferring, when the fold is provably safe:
//   - entities only: a second same-key RELATION's existence check is an ES search
//     (getExistingRelations) that cannot see buffered writes; the in-memory replica is T5,
//     out of scope;
//   - no enforced-reference commit (it keeps its own write and event; E8 never merges
//     commit-carrying updates) and no eventId/synchronizedUpsert replay context (their
//     i_attributes freshness checks read a state the chained basis does not carry).
// The remaining conditions (target resolved before the batch, no forceDirect on either
// side) are checked at the chain, not the intent.
const isFoldable = (intent: SequencerIntent): boolean => intent.kind === 'entity'
  && !(intent.opts?.references?.length > 0)
  && !intent.context?.eventId
  && !intent.context?.synchronizedUpsert;

interface ChainStep {
  leader: SequencerIntent;
  absorbed: SequencerIntent[];
  norm: string;
}

interface Chain {
  steps: ChainStep[];
  // a new step may append only while every current member is fold-safe AND the target
  // existed before the batch (a same-batch creation is not a valid with-refs basis:
  // buildEntityData strips the ref input fields from the created element, so diffing
  // against it would re-ADD its refs and duplicate meta relations)
  foldEligible: boolean;
  resolvedTarget: boolean;
}

// forceDirect: intents whose parking deadline has passed; they apply through the unchanged
// path regardless of unresolved references (which then behaves exactly as today).
export interface BatchPlanOptions {
  // D2 v3: park a soft ref whose producer is neither resolved nor in the batch. Off by
  // default (v2 semantics): blind soft parking deadlocks against a bounded prefetch
  // window (plan 0009 §8.8), it only makes sense when the transport guarantees the
  // producer can still be delivered.
  parkSoftRefs?: boolean;
}

export const buildBatchPlan = (
  batch: SequencerIntent[],
  resolveId: (id: string) => string | null,
  forceDirect: Set<string> = new Set(),
  options: BatchPlanOptions = {},
): BatchPlan => {
  // 1. coalescing (D3) and chaining (P2): one Chain per canonical key. An identical norm
  // absorbs into its step; a different norm appends a chain step when fold-safe, else
  // defers to the next batch (residual).
  const chainsByKey = new Map<string, Chain>();
  const deferred: { intent: SequencerIntent; reason: DeferReason }[] = [];
  let chainedSteps = 0;
  batch.forEach((intent) => {
    const key = canonicalKey(intent, resolveId);
    const norm = `${intent.kind}:${intent.type}:${stableStringify(intent.input)}`;
    const chain = chainsByKey.get(key);
    if (!chain) {
      const resolvedTarget = intent.kind === 'entity' && intent.candidateIds.some((id) => resolveId(id) !== null);
      chainsByKey.set(key, {
        steps: [{ leader: intent, absorbed: [], norm }],
        foldEligible: resolvedTarget && isFoldable(intent) && !forceDirect.has(intent.id),
        resolvedTarget,
      });
      return;
    }
    const sameStep = chain.steps.find((step) => step.norm === norm);
    if (sameStep) {
      sameStep.absorbed.push(intent);
    } else if (chain.foldEligible && isFoldable(intent) && !forceDirect.has(intent.id)) {
      chain.steps.push({ leader: intent, absorbed: [], norm });
      chainedSteps += 1;
    } else {
      // residual deferral: relations, same-batch creations, commits/replays, forceDirect
      // companions (a forceDirect same-key intent defers rather than joining the chain:
      // it would apply out of order against a stale basis). The reason records WHICH
      // clause refused the chain (P2 diagnosis, s9.7.6 A/B reading).
      let reason: DeferReason;
      if (intent.kind !== 'entity') reason = 'relation';
      else if (forceDirect.has(intent.id)) reason = 'force_direct';
      else if (!isFoldable(intent)) reason = 'self_not_foldable';
      else if (!chain.resolvedTarget) reason = 'unresolved_target';
      else reason = 'head_not_foldable';
      deferred.push({ intent, reason });
    }
  });
  // explode chains into plan groups, step order preserved; chainPrev[i] = the group index
  // of the step's predecessor in its chain (-1 for chain heads)
  const groups: ChainStep[] = [];
  const chainPrev: number[] = [];
  chainsByKey.forEach((chain) => {
    chain.steps.forEach((step, stepIndex) => {
      groups.push(step);
      chainPrev.push(stepIndex === 0 ? -1 : groups.length - 2);
    });
  });
  // 2. producers: candidate ids of every leader (absorbed assert the same target). Chain
  // heads register their ids first (insertion order), so consumers of a chained target
  // order after step 1, which provides existence.
  const producers = new Map<string, number>();
  groups.forEach((group, index) => {
    group.leader.candidateIds.forEach((id) => {
      if (!producers.has(id)) producers.set(id, index);
    });
  });
  // 3. edges and parking (D2)
  const parked: { intent: SequencerIntent; missing: string[] }[] = [];
  const edges: Set<number>[] = groups.map(() => new Set());
  const applicable: boolean[] = groups.map(() => true);
  const missingByGroup = new Map<number, string[]>();
  groups.forEach((group, index) => {
    if (forceDirect.has(group.leader.id)) return; // expired: apply as-is, no deps, no parking
    // P2 chain edge: each step orders after its predecessor (its diff basis is the
    // predecessor's in-memory result); the parking fixpoint below parks a whole chain
    // when its head parks
    if (chainPrev[index] >= 0) edges[index].add(chainPrev[index]);
    const missing: string[] = [];
    hardDependencyIds(group.leader).forEach((id) => {
      if (resolveId(id)) return;
      const producer = producers.get(id);
      if (producer !== undefined && producer !== index) {
        edges[index].add(producer);
      } else if (producer === undefined) {
        missing.push(id);
      }
    });
    softDependencyIds(group.leader).forEach((id) => {
      if (resolveId(id)) return;
      const producer = producers.get(id);
      if (producer !== undefined && producer !== index) {
        edges[index].add(producer); // order after the in-batch producer
      } else if (options.parkSoftRefs && producer === undefined && !isAutoCreatedRef(id)) {
        missing.push(id); // D2 v3 (opt-in): the producer may be in flight, park until it lands
      }
    });
    if (missing.length > 0) {
      applicable[index] = false;
      missingByGroup.set(index, missing);
    }
  });
  // a consumer whose in-batch producer is itself parked cannot apply either: park it too
  // (its missing ids are the producer's), iterated to a fixpoint
  let changed = true;
  while (changed) {
    changed = false;
    groups.forEach((group, index) => {
      if (!applicable[index] || forceDirect.has(group.leader.id)) return;
      const blockedDep = Array.from(edges[index]).find((dep) => !applicable[dep]);
      if (blockedDep !== undefined) {
        applicable[index] = false;
        missingByGroup.set(index, missingByGroup.get(blockedDep) ?? groups[blockedDep].leader.candidateIds.slice(0, 1));
        changed = true;
      }
    });
  }
  groups.forEach((group, index) => {
    if (applicable[index]) return;
    const missing = missingByGroup.get(index) ?? [];
    parked.push({ intent: group.leader, missing });
    // absorbed follow their leader to parking: they resolve with the same application
    group.absorbed.forEach((a) => parked.push({ intent: a, missing }));
  });
  // 4. topological order among applicable groups, (phase, arrival) priority, cycles broken
  // by taking the lowest-priority remaining node
  const priority = (index: number) => {
    const { leader } = groups[index];
    return [classifyPhase(leader), leader.arrivedAt, index] as const;
  };
  const remaining = new Set<number>(groups.map((_, i) => i).filter((i) => applicable[i]));
  const done = new Set<number>();
  const order: CoalesceGroup[] = [];
  while (remaining.size > 0) {
    const ready = Array.from(remaining)
      .filter((i) => Array.from(edges[i]).every((dep) => done.has(dep) || !applicable[dep]));
    const pool = ready.length > 0 ? ready : Array.from(remaining); // cycle: break by priority
    pool.sort((a, b) => {
      const pa = priority(a);
      const pb = priority(b);
      if (pa[0] !== pb[0]) return pa[0] - pb[0];
      if (pa[1] !== pb[1]) return pa[1] - pb[1];
      return pa[2] - pb[2];
    });
    const next = pool[0];
    remaining.delete(next);
    done.add(next);
    order.push({ leader: groups[next].leader, absorbed: groups[next].absorbed });
  }
  return { order, deferred, parked, chainedSteps };
};
