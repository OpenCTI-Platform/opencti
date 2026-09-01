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
  // s9.9: positions (within BatchPlan.order) of this group's applicable producers. The
  // loop uses them to SKIP a consumer whose producer failed mid-batch instead of letting
  // it apply and fail in cascade.
  dependsOn?: number[];
}

// P2 diagnosis reasons (s9.7.4) + iteration-3 certainty reasons (s9.8.2): queued_producer =
// the missing in-bundle ref is physically in the queue (one-batch wait, no deadline);
// member_wait = declared in-bundle but not seen yet (transport jitter, bounded attempts)
export type DeferReason = 'relation' | 'force_direct' | 'self_not_foldable' | 'head_not_foldable' | 'unresolved_target'
  | 'queued_producer' | 'member_wait' | 'failed_producer';

export interface BatchPlan {
  order: CoalesceGroup[];
  deferred: { intent: SequencerIntent; reason: DeferReason }[];
  parked: { intent: SequencerIntent; missing: string[] }[];
  // s9.8.2 "member dead": a ref declared in-bundle, absent everywhere after the bounded
  // wait: its producer failed, no retry can help. The loop rejects with final: true and
  // the worker drops (hard) or strips-and-resends (soft) the object, never the bundle.
  finalMissing: { intent: SequencerIntent; missing: string[] }[];
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
  // s9.8: queue index lookup (candidate ids of QUEUED intents). Absent = classification
  // degrades to external-only (today's behavior).
  queueHas?: (id: string) => boolean;
  // s9.8.2 K: plan passes a member ref may stay unseen (transport jitter) before it is
  // declared dead
  memberWaitLimit?: number;
}

// s9.8.2 classification of ONE missing id (not resolved, no in-batch producer):
//   - declared in-bundle and in the queue -> certain one-batch wait;
//   - declared in-bundle, not seen, under the attempt limit -> bounded wait;
//   - declared in-bundle, not seen, limit reached -> its producer failed: final;
//   - not declared (or no annotation) -> external: today's behavior.
type MissingClass = 'queued_producer' | 'member_wait' | 'member_dead' | 'external';
const classifyMissing = (intent: SequencerIntent, id: string, options: BatchPlanOptions): MissingClass => {
  if (!intent.memberRefIds?.has(id)) return 'external';
  if (options.queueHas?.(id)) return 'queued_producer';
  if ((intent.memberWaitAttempts ?? 0) >= (options.memberWaitLimit ?? 2)) return 'member_dead';
  return 'member_wait';
};

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
  // 3. edges, and classification of unresolved refs (D2 + s9.8.2 certainty rules)
  const parked: { intent: SequencerIntent; missing: string[] }[] = [];
  const finalMissing: { intent: SequencerIntent; missing: string[] }[] = [];
  const edges: Set<number>[] = groups.map(() => new Set());
  const applicable: boolean[] = groups.map(() => true);
  const missingByGroup = new Map<number, string[]>();
  const groupClass = new Map<number, 'parked' | 'defer' | 'final'>();
  const deferReasonByGroup = new Map<number, DeferReason>();
  groups.forEach((group, index) => {
    if (forceDirect.has(group.leader.id)) return; // expired: apply as-is, no deps, no parking
    // P2 chain edge: each step orders after its predecessor (its diff basis is the
    // predecessor's in-memory result); the parking fixpoint below parks a whole chain
    // when its head parks
    if (chainPrev[index] >= 0) edges[index].add(chainPrev[index]);
    const parkIds: string[] = [];
    const finalIds: string[] = [];
    let defer: DeferReason | null = null;
    const onMissing = (id: string, soft: boolean) => {
      const cls = classifyMissing(group.leader, id, options);
      if (cls === 'member_wait') {
        defer = 'member_wait'; // dominates queued_producer: this pass counts an attempt
      } else if (cls === 'queued_producer') {
        defer = defer ?? 'queued_producer';
      } else if (cls === 'member_dead') {
        finalIds.push(id);
      } else if (!soft) {
        parkIds.push(id); // external hard: park with deadline, today's healing path
      } else if (options.parkSoftRefs) {
        parkIds.push(id); // D2 v3 (opt-in): external soft park
      } // external soft, default: apply as today (may reject at apply, worker retries)
    };
    hardDependencyIds(group.leader).forEach((id) => {
      if (resolveId(id)) return;
      const producer = producers.get(id);
      if (producer !== undefined && producer !== index) {
        edges[index].add(producer);
      } else if (producer === undefined) {
        onMissing(id, false);
      }
    });
    softDependencyIds(group.leader).forEach((id) => {
      if (resolveId(id)) return;
      const producer = producers.get(id);
      if (producer !== undefined && producer !== index) {
        edges[index].add(producer); // order after the in-batch producer
      } else if (producer === undefined && !isAutoCreatedRef(id)) {
        onMissing(id, true);
      }
    });
    if (finalIds.length > 0) {
      // a dead member ref condemns the intent regardless of its other refs: reject now,
      // the worker strips (soft) or drops (hard) and a resent object re-enters fresh
      applicable[index] = false;
      groupClass.set(index, 'final');
      missingByGroup.set(index, finalIds);
    } else if (defer) {
      applicable[index] = false;
      groupClass.set(index, 'defer');
      deferReasonByGroup.set(index, defer);
      if (defer === 'member_wait') {
        group.leader.memberWaitAttempts = (group.leader.memberWaitAttempts ?? 0) + 1;
      }
    } else if (parkIds.length > 0) {
      applicable[index] = false;
      missingByGroup.set(index, parkIds);
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
    const cls = groupClass.get(index) ?? 'parked'; // fixpoint-blocked consumers default to parked
    if (cls === 'final') {
      finalMissing.push({ intent: group.leader, missing });
      group.absorbed.forEach((a) => finalMissing.push({ intent: a, missing }));
    } else if (cls === 'defer') {
      const reason = deferReasonByGroup.get(index) as DeferReason;
      deferred.push({ intent: group.leader, reason });
      group.absorbed.forEach((a) => deferred.push({ intent: a, reason }));
    } else {
      parked.push({ intent: group.leader, missing });
      // absorbed follow their leader to parking: they resolve with the same application
      group.absorbed.forEach((a) => parked.push({ intent: a, missing }));
    }
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
  const orderPosition = new Map<number, number>(); // group index -> position in order
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
    // s9.9: expose the applicable producers as order positions (emitted earlier by
    // construction; a cycle-broken edge may point forward and is then omitted)
    const dependsOn = Array.from(edges[next])
      .filter((dep) => applicable[dep] && orderPosition.has(dep))
      .map((dep) => orderPosition.get(dep) as number);
    orderPosition.set(next, order.length);
    order.push({ leader: groups[next].leader, absorbed: groups[next].absorbed, dependsOn });
  }
  return { order, deferred, parked, finalMissing, chainedSteps };
};
