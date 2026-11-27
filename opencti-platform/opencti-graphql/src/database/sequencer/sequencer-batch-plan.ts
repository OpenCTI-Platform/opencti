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
import { intentEndpointIds, intentOwnIds } from './sequencer-intent';
import type { SequencerIntent } from './sequencer-intent';
import { getDraftContext } from '../../utils/draftContext';

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
  // waitingOn (B10): the ids classified queued_producer, the deferral waits for their landing
  deferred: { intent: SequencerIntent; reason: DeferReason; waitingOn?: string[] }[];
  parked: { intent: SequencerIntent; missing: string[] }[];
  // s9.8.2 "member dead": a ref declared in-bundle, absent everywhere after the bounded
  // wait: its producer failed, no retry can help. The loop rejects with final: true and
  // the worker drops (hard) or strips-and-resends (soft) the object, never the bundle.
  finalMissing: { intent: SequencerIntent; missing: string[] }[];
  // s9.10.2: dead member refs that were SOFT: stripped from the surviving intent's input
  // (the container applies without the edge that could never exist) instead of condemning
  // the whole object. Only hard dead refs (relation endpoints) still reject final.
  strippedDead: { intent: SequencerIntent; stripped: string[] }[];
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

// A Date by its instant, any other non plain object (an upload, a promise) by its identity: an
// object walk reads them all as {}, and two inputs differing only there would coalesce (task 0040,
// review 2026-11-25: the absorbed intent's dates never applied). GraphQL input objects have a null
// prototype and are walked.
const objectIds = new WeakMap<object, number>();
let lastObjectId = 0;
const objectIdOf = (value: object): number => {
  let id = objectIds.get(value);
  if (id === undefined) {
    lastObjectId += 1;
    id = lastObjectId;
    objectIds.set(value, id);
  }
  return id;
};

const stableStringify = (value: any): string => {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (value instanceof Date) return `d${value.getTime()}`;
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return `o${objectIdOf(value)}`;
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
  // Key on the STANDARD id alone (getInputIds puts it first: it IS the entity's identity), not
  // on the whole candidate list. Found 2026-09-21 (MITRE, chunk 48 and concurrent apply): the
  // same malware asserted by two bundles under two STIX ids had two candidate lists, hence two
  // keys, two groups in one batch, and the second create never saw the first's fresh in-batch
  // write: two documents per standard id. With one key the twins share a chain and the second
  // defers one batch, as every same-target different-input creation on an unknown target does.
  return `e:${intent.candidateIds[0]}`;
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

// Fix 2026-09-21: the own set is the intent's OWN ids, never its endpoints. candidateIds
// carry fromId/toId for relations (intake shape, plan B2), so filtering on candidateIds
// dropped every endpoint from the hard dependencies: relations were admitted with absent
// endpoints, failed at apply (MISSING_REFERENCE) and went through retention. Found on
// MITRE at chunk 48 (601 retained per run, all relation endpoints, probe 2026-09-21).
const hardDependencyIds = (intent: SequencerIntent): string[] => {
  const own = new Set(intentOwnIds(intent));
  return intentEndpointIds(intent).filter((id) => !own.has(id));
};

const softDependencyIds = (intent: SequencerIntent): string[] => {
  const own = new Set(intentOwnIds(intent));
  const endpoints = new Set(intentEndpointIds(intent)); // hard, handled above
  return intent.referencedIds.filter((id) => typeof id === 'string' && id.length > 0 && !own.has(id) && !endpoints.has(id));
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
  // computed on demand, only once a second intent lands on the same key (most keys have one)
  norm?: string;
}

// Besides the input, what makes an apply differ (task 0040 review 2026-11-25): the user (each upsert records
// its creator_id under its own confidence), the opts, and the context the apply and its failure path read
// (replay freshness, full sync, previous standard id, draft, create-only form import, retention of a missing
// reference, the reject-twice of an unresolved optional ref while the worker retry number is at most 2,
// middleware.ts createRelationRaw), and the origin its events carry (the connector, the playbook: pycti sets the
// playbook per object, the playbook manager skips the events of its own playbook). An intent absorbed by a leader
// differing there would never apply as itself.
// Absorbed intents still follow their leader's member annotations (memberRefIds, memberWaitAttempts) in the
// routing below: a declared member classified dead is retained (deferMissingRefs, equal by the norm) or
// stripped and reconciled, never dropped.
const rejectsOptionalRefsOf = (intent: SequencerIntent): boolean => {
  const retry: any = intent.user?.origin?.call_retry_number;
  return retry !== undefined && retry !== null && retry !== '' && !!retry && retry <= 2;
};
const applyContextOf = (intent: SequencerIntent) => ({
  applicant: intent.user?.origin?.applicant_id ?? null,
  playbook: intent.user?.origin?.playbook_id ?? null,
  eventId: intent.context?.eventId ?? null,
  synchronizedUpsert: !!intent.context?.synchronizedUpsert,
  previousStandard: intent.context?.previousStandard ?? null,
  draft: getDraftContext(intent.context, intent.user) ?? null,
  formSubmission: intent.context?.form_submission === true,
  deferMissingRefs: !!intent.context?.deferMissingRefs,
  rejectsOptionalRefs: rejectsOptionalRefsOf(intent),
});
const normOf = (intent: SequencerIntent): string => `${intent.kind}:${intent.type}:${intent.user?.id ?? ''}:${stableStringify(intent.opts ?? {})}:${stableStringify(applyContextOf(intent))}:${stableStringify(intent.input)}`;

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
//   - producer visible in the queue -> certain one-batch wait, WHATEVER the ref's origin
//     (s9.10.2: the queue index is the same certainty as a member declaration; before this
//     an external ref whose producer sat in the queue failed the apply and burnt the
//     worker's retry budget, measured ch16-e: 5,037 external roots);
//   - declared in-bundle, not seen, under the attempt limit -> bounded wait;
//   - declared in-bundle, not seen, limit reached -> its producer failed: final;
//   - not declared (or no annotation), not queued -> external: today's behavior.
type MissingClass = 'queued_producer' | 'member_wait' | 'member_dead' | 'external';
const classifyMissing = (intent: SequencerIntent, id: string, options: BatchPlanOptions): MissingClass => {
  if (options.queueHas?.(id)) return 'queued_producer';
  if (!intent.memberRefIds?.has(id)) return 'external';
  if ((intent.memberWaitAttempts ?? 0) >= (options.memberWaitLimit ?? 2)) return 'member_dead';
  return 'member_wait';
};

// s9.10.2 member-dead soft-strip: remove the dead ids everywhere in the input, in place
// (string entries leave their array, scalar ref fields null out). The apply closure holds
// this same object, so the direct path creates the element without the dead references,
// deterministically and in zero extra round trips (the upstream reject-twice heuristic
// reaches the same end state after 2 blind worker retries).
// Verdict 31 (write-path reference note): a "dead" member is usually just LATE (proven:
// the stripped edges were THE dominant estate loss, and their members existed in the
// final estate), so every removal is recorded on the intent (input key + ref id) and
// harvested into the pending-refs store after the apply: strip = deferred edge, not loss.
const stripDeadRefIds = (value: any, deadIds: Set<string>, onStrip: (refId: string) => void): void => {
  if (Array.isArray(value)) {
    for (let i = value.length - 1; i >= 0; i -= 1) {
      const entry = value[i];
      if (typeof entry === 'string' && deadIds.has(entry)) {
        value.splice(i, 1);
        onStrip(entry);
      } else if (entry !== null && typeof entry === 'object') stripDeadRefIds(entry, deadIds, onStrip);
    }
    return;
  }
  if (value !== null && typeof value === 'object') {
    Object.keys(value).forEach((key) => {
      const v = value[key];
      if (typeof v === 'string' && deadIds.has(v)) {
        value[key] = null;
        onStrip(v);
      } else if (v !== null && typeof v === 'object') stripDeadRefIds(v, deadIds, onStrip);
    });
  }
};

const stripDeadFromIntent = (intent: SequencerIntent, deadIds: Set<string>): void => {
  Object.keys(intent.input).forEach((inputKey) => {
    const v = intent.input[inputKey];
    const onStrip = (refId: string) => {
      (intent.deadStrippedRefs ??= []).push({ inputKey, refId });
    };
    if (typeof v === 'string' && deadIds.has(v)) {
      intent.input[inputKey] = null;
      onStrip(v);
    } else if (v !== null && typeof v === 'object') {
      stripDeadRefIds(v, deadIds, onStrip);
    }
  });
  intent.referencedIds = intent.referencedIds.filter((id) => !deadIds.has(id));
  deadIds.forEach((id) => intent.memberRefIds?.delete(id));
};

// Step 4 of buildBatchPlan. Same output as the former O(n^2 log n) loop (each pass re-filtered
// every remaining node and re-sorted the ready pool): priority (phase, arrivedAt, index), a
// non-applicable dep never blocks, a cycle emits the lowest-priority remaining node, and
// dependsOn lists the order positions of the applicable deps already emitted (a cycle-broken
// edge may point forward and is then omitted). Exported for its oracle test.
export const orderApplicable = (groups: { leader: SequencerIntent; absorbed: SequencerIntent[] }[], edges: Set<number>[], applicable: boolean[]): CoalesceGroup[] => {
  const n = groups.length;
  const phase = new Int8Array(n);
  const arrived = new Float64Array(n);
  const indegree = new Int32Array(n);
  const dependents: number[][] = new Array(n);
  const nodes: number[] = [];
  for (let i = 0; i < n; i += 1) {
    if (applicable[i]) {
      phase[i] = classifyPhase(groups[i].leader);
      arrived[i] = groups[i].leader.arrivedAt;
      nodes.push(i);
      edges[i].forEach((dep) => {
        if (!applicable[dep]) return;
        indegree[i] += 1;
        (dependents[dep] ??= []).push(i);
      });
    }
  }
  const less = (a: number, b: number): boolean => {
    if (phase[a] !== phase[b]) return phase[a] < phase[b];
    const d = arrived[a] - arrived[b];
    if (d < 0) return true;
    if (d > 0) return false;
    return a < b;
  };
  const heap: number[] = [];
  const push = (v: number) => {
    let k = heap.length;
    heap.push(v);
    while (k > 0) {
      const p = (k - 1) >> 1;
      if (!less(v, heap[p])) break;
      heap[k] = heap[p];
      k = p;
    }
    heap[k] = v;
  };
  const pop = (): number => {
    const top = heap[0];
    const last = heap.pop() as number;
    if (heap.length > 0) {
      let k = 0;
      for (;;) {
        const l = 2 * k + 1;
        if (l >= heap.length) break;
        const r = l + 1;
        const c = r < heap.length && less(heap[r], heap[l]) ? r : l;
        if (!less(heap[c], last)) break;
        heap[k] = heap[c];
        k = c;
      }
      heap[k] = last;
    }
    return top;
  };
  nodes.forEach((i) => {
    if (indegree[i] === 0) push(i);
  });
  // cycle-break pool, sorted by priority only once a cycle is met; the cursor skips done nodes
  let byPriority: number[] | null = null;
  let cursor = 0;
  const done = new Uint8Array(n);
  const position = new Int32Array(n).fill(-1); // group index -> position in order
  const order: CoalesceGroup[] = [];
  while (order.length < nodes.length) {
    let next: number;
    if (heap.length > 0) {
      next = pop();
    } else {
      byPriority ??= nodes.slice().sort((a, b) => (less(a, b) ? -1 : 1));
      while (done[byPriority[cursor]]) cursor += 1;
      next = byPriority[cursor];
    }
    done[next] = 1;
    const nextDependents = dependents[next];
    if (nextDependents) {
      for (let j = 0; j < nextDependents.length; j += 1) {
        const d = nextDependents[j];
        indegree[d] -= 1;
        // a node emitted by a cycle break is never pushed again
        if (indegree[d] === 0 && !done[d]) push(d);
      }
    }
    // s9.9: expose the applicable producers as order positions
    const dependsOn: number[] = [];
    edges[next].forEach((dep) => {
      if (applicable[dep] && position[dep] >= 0) dependsOn.push(position[dep]);
    });
    position[next] = order.length;
    order.push({ leader: groups[next].leader, absorbed: groups[next].absorbed, dependsOn });
  }
  return order;
};

// task 0050 lead 38: the lane of a key is a FIFO, so the deferrals of one key go to it oldest first (arrivedAt, then
// batch index), each key keeping its positions in the list. A companion waiting on the same queued producer as its
// older head took its step-1 slot ahead of it: both woke on the landing and the newer write applied first
// (review 2026-11-25). The batch index alone is not the age: the loop puts a fresh arrival ahead of the parked set.
// Exported for its property test.
export const inArrivalOrderPerKey = <D extends { intent: SequencerIntent }>(
  deferrals: D[],
  batch: SequencerIntent[],
  resolveId: (id: string) => string | null,
): D[] => {
  const batchIndex = new Map(batch.map((intent, index) => [intent.id, index]));
  const positionsByKey = new Map<string, number[]>();
  deferrals.forEach(({ intent }, position) => {
    const key = canonicalKey(intent, resolveId);
    const positions = positionsByKey.get(key);
    if (positions) positions.push(position);
    else positionsByKey.set(key, [position]);
  });
  const ordered = [...deferrals];
  positionsByKey.forEach((positions) => {
    const entries = positions.map((position) => deferrals[position]).sort((a, b) => a.intent.arrivedAt - b.intent.arrivedAt
      || (batchIndex.get(a.intent.id) ?? 0) - (batchIndex.get(b.intent.id) ?? 0));
    positions.forEach((position, rank) => {
      ordered[position] = entries[rank];
    });
  });
  return ordered;
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
  type Deferral = { intent: SequencerIntent; reason: DeferReason; waitingOn?: string[] };
  // residual deferrals of step 1, in batch order, ahead of the group deferrals; a companion's slot is filled once it
  // is routed (empty when it parks)
  const residual: (Deferral | null)[] = [];
  const deferred: Deferral[] = [];
  // task 0040 lead 36: same-key intents refused by their chain (not expired), routed after the plan
  const companions: { intent: SequencerIntent; reason: DeferReason; slot: number }[] = [];
  let chainedSteps = 0;
  batch.forEach((intent) => {
    const key = canonicalKey(intent, resolveId);
    const chain = chainsByKey.get(key);
    if (!chain) {
      const resolvedTarget = intent.kind === 'entity' && intent.candidateIds.some((id) => resolveId(id) !== null);
      chainsByKey.set(key, {
        steps: [{ leader: intent, absorbed: [] }],
        foldEligible: resolvedTarget && isFoldable(intent) && !forceDirect.has(intent.id),
        resolvedTarget,
      });
      return;
    }
    // lazy norms: still inside this loop, before any dead strip mutates an input
    const norm = normOf(intent);
    // task 0040 lead 36: an expired intent never joins a fresh leader (nor the reverse): it would park again past
    // its deadline with the group
    const expired = forceDirect.has(intent.id);
    const sameStep = chain.steps.find((step) => {
      step.norm ??= normOf(step.leader);
      return step.norm === norm && forceDirect.has(step.leader.id) === expired;
    });
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
      // task 0040 lead 36: an expired one goes to its lane at once; the others are routed once the plan is known
      if (forceDirect.has(intent.id)) {
        residual.push({ intent, reason });
      } else {
        companions.push({ intent, reason, slot: residual.length });
        residual.push(null);
      }
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
  // task 0040: an intent deferred above (same target, another input) is in flight: it goes to its
  // lane and lands in a later batch. A container waiting for it waits for a certain producer,
  // not for a declared member still unseen (which would burn its bounded member wait: two such
  // passes behind a busy relation target stripped the container's refs, multi-writer diag).
  const deferredOwnIds = new Set([...residual.filter((entry) => entry !== null), ...companions].flatMap(({ intent }) => intentOwnIds(intent)));
  const inFlight = (id: string) => deferredOwnIds.has(id) || (options.queueHas?.(id) ?? false);
  const planOptions: BatchPlanOptions = { ...options, queueHas: inFlight };
  // 2. producers: candidate ids of every leader (absorbed assert the same target). Chain
  // heads register their ids first (insertion order), so consumers of a chained target
  // order after step 1, which provides existence.
  const producers = new Map<string, number>();
  groups.forEach((group, index) => {
    // own ids only (fix 2026-09-21): a relation is not the producer of its endpoints
    intentOwnIds(group.leader).forEach((id) => {
      if (!producers.has(id)) producers.set(id, index);
    });
  });
  // 3. edges, and classification of unresolved refs (D2 + s9.8.2 certainty rules)
  const parked: { intent: SequencerIntent; missing: string[] }[] = [];
  const finalMissing: { intent: SequencerIntent; missing: string[] }[] = [];
  const strippedDead: { intent: SequencerIntent; stripped: string[] }[] = [];
  const edges: Set<number>[] = groups.map(() => new Set());
  const applicable: boolean[] = groups.map(() => true);
  const missingByGroup = new Map<number, string[]>();
  const groupClass = new Map<number, 'parked' | 'defer' | 'final'>();
  const deferReasonByGroup = new Map<number, DeferReason>();
  const waitingByGroup = new Map<number, string[]>();
  // The dependencies of one intent against this batch (D2 + s9.8.2 certainty rules), without side effect: the
  // routing of a group applies them below; a companion is classified the same way (task 0040 lead 36).
  // self: the group the intent leads (its own producer), -1 for a companion
  const dependenciesOf = (intent: SequencerIntent, self: number) => {
    const edgesTo: number[] = [];
    const parkIds: string[] = [];
    const finalIds: string[] = [];
    const deadSoftIds: string[] = [];
    const waiting: string[] = [];
    let defer: DeferReason | null = null;
    const onMissing = (id: string, soft: boolean) => {
      const cls = classifyMissing(intent, id, planOptions);
      if (cls === 'member_wait') {
        defer = 'member_wait'; // dominates queued_producer: this pass counts an attempt
      } else if (cls === 'queued_producer') {
        defer = defer ?? 'queued_producer';
        waiting.push(id);
      } else if (cls === 'member_dead') {
        // s9.10.2: a dead SOFT ref is stripped (the container survives without the edge
        // that could never exist). A dead HARD ref (relation endpoint) condemns the intent
        // as FINAL only when the caller has a retention store behind it (the chunk path:
        // the loop retains the creation and re-submits it when the member lands). Fix
        // 2026-09-24 (B16): without retention (the HTTP path), "dead" is usually just LATE
        // over another pool and a final rejection is a drop the client never retries
        // (3,330 relationships lost on one full-mix run); it parks with the deadline instead,
        // then applies as today (reject, worker retry ladder).
        if (soft) deadSoftIds.push(id);
        else if (intent.context?.deferMissingRefs) finalIds.push(id);
        else parkIds.push(id);
      } else if (!soft) {
        parkIds.push(id); // external hard: park with deadline, today's healing path
      } else if (options.parkSoftRefs) {
        parkIds.push(id); // D2 v3 (opt-in): external soft park
      } // external soft, default: apply as today (may reject at apply, worker retries)
    };
    hardDependencyIds(intent).forEach((id) => {
      if (resolveId(id)) return;
      const producer = producers.get(id);
      if (producer !== undefined && producer !== self) {
        edgesTo.push(producer);
      } else if (producer === undefined) {
        onMissing(id, false);
      }
    });
    softDependencyIds(intent).forEach((id) => {
      if (resolveId(id)) return;
      const producer = producers.get(id);
      if (producer !== undefined && producer !== self) {
        edgesTo.push(producer); // order after the in-batch producer
      } else if (producer === undefined) {
        // Auto-created families skip the missing path only when nothing is in flight for
        // them (the D2 v1 lesson above). Since the single wave per chunk (2026-09-24) pycti's
        // pre-created labels, external references and kill chain phases DO arrive as producer
        // intents resolved by standard id: a ref to one that is queued, or declared an
        // in-chunk member, waits for its producer like any other (probe 2026-09-24: 86
        // course-of-action label refs per MITRE run applied with the producer still queued
        // and were stripped, then reconciled one intent per cycle).
        const producerInFlight = inFlight(id) || intent.memberRefIds?.has(id);
        if (!isAutoCreatedRef(id) || producerInFlight) onMissing(id, true);
      }
    });
    return { edgesTo, parkIds, finalIds, deadSoftIds, waiting, defer: defer as DeferReason | null };
  };
  groups.forEach((group, index) => {
    if (forceDirect.has(group.leader.id)) return; // expired: apply as-is, no deps, no parking
    // P2 chain edge: each step orders after its predecessor (its diff basis is the
    // predecessor's in-memory result); the parking fixpoint below parks a whole chain
    // when its head parks
    if (chainPrev[index] >= 0) edges[index].add(chainPrev[index]);
    const { edgesTo, parkIds, finalIds, deadSoftIds, waiting, defer } = dependenciesOf(group.leader, index);
    edgesTo.forEach((dep) => edges[index].add(dep));
    if (waiting.length > 0) waitingByGroup.set(index, waiting);
    // s9.10.2 strip point: a group not condemned by a hard dead ref sheds its dead soft
    // refs HERE, before routing, so whatever path it takes (apply now, defer, park) it
    // travels clean (absorbed re-enter individually on defer: strip them too, their
    // inputs are distinct objects with equal content)
    if (finalIds.length === 0 && deadSoftIds.length > 0) {
      const dead = new Set(deadSoftIds);
      [group.leader, ...group.absorbed].forEach((intent) => {
        stripDeadFromIntent(intent, dead);
        strippedDead.push({ intent, stripped: deadSoftIds });
      });
    }
    if (finalIds.length > 0) {
      // a dead HARD ref condemns the intent regardless of its other refs: reject now,
      // pycti reports-and-drops the object in one round trip (a relation without its
      // endpoint is meaningless)
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
      // only a queued_producer deferral waits; member_wait dominates and stays a bounded re-plan
      const waitingOn = reason === 'queued_producer' ? waitingByGroup.get(index) : undefined;
      deferred.push({ intent: group.leader, reason, waitingOn });
      group.absorbed.forEach((a) => deferred.push({ intent: a, reason, waitingOn }));
    } else {
      parked.push({ intent: group.leader, missing });
      // absorbed follow their leader to parking: they resolve with the same application
      group.absorbed.forEach((a) => parked.push({ intent: a, missing }));
    }
  });
  // task 0040 lead 36: a same-key intent refused by its chain waits the way it would as a head: on a queued producer
  // or a declared member (their own bounds), or parked on a missing reference with no producer in sight or behind
  // an in-batch producer that does not apply; otherwise in its lane with its reason. Its park clock is kept
  // (sequencer-park-book.ts). Sent to its lane while blocked, it came back first in the next batch, became the head
  // and parked while the former head went to the lane: the two alternated every cycle until their deadlines (review
  // 2026-11-25: two connectors asserting one relationship, staggered arrivals, a head blocked behind a parked
  // in-batch producer, same-key reports); sent there while its producer was queued, it waited behind the lane's
  // B10 head on its park clock instead of its B10 bound.
  companions.forEach(({ intent, reason, slot }) => {
    const { edgesTo, parkIds, finalIds, waiting, defer } = dependenciesOf(intent, -1);
    const blockedBy = edgesTo.find((dep) => !applicable[dep]);
    if (finalIds.length > 0) {
      residual[slot] = { intent, reason }; // condemned as a head next batch, where the retention path applies
    } else if (defer === 'queued_producer') {
      residual[slot] = { intent, reason: defer, waitingOn: waiting };
    } else if (defer === 'member_wait') {
      intent.memberWaitAttempts = (intent.memberWaitAttempts ?? 0) + 1; // a pass, as for a head: bounded
      residual[slot] = { intent, reason: defer };
    } else if (parkIds.length > 0) {
      parked.push({ intent, missing: parkIds });
    } else if (blockedBy !== undefined) {
      parked.push({ intent, missing: missingByGroup.get(blockedBy) ?? groups[blockedBy].leader.candidateIds.slice(0, 1) });
    } else {
      residual[slot] = { intent, reason };
    }
  });
  // 4. topological order among applicable groups, (phase, arrival) priority, cycles broken
  // by taking the lowest-priority remaining node. Kahn over a binary min-heap; phase and
  // arrival read once per group, here (the step-3 dead strip can change the phase)
  const order = orderApplicable(groups, edges, applicable);
  const deferrals = [...residual.filter((entry): entry is Deferral => entry !== null), ...deferred];
  return { order, deferred: inArrivalOrderPerKey(deferrals, batch, resolveId), parked, finalMissing, strippedDead, chainedSteps };
};
