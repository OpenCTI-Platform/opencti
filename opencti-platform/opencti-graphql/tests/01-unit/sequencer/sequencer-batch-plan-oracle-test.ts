import { describe, expect, it } from 'vitest';
import { buildBatchPlan, canonicalKey, classifyPhase, orderApplicable } from '../../../src/database/sequencer/sequencer-batch-plan';
import type { BatchPlan, BatchPlanOptions, CoalesceGroup, DeferReason } from '../../../src/database/sequencer/sequencer-batch-plan';
import { intentEndpointIds, intentOwnIds } from '../../../src/database/sequencer/sequencer-intent';
import type { SequencerIntent } from '../../../src/database/sequencer/sequencer-intent';

// Oracle for the step-4 Kahn order and the lazy coalescing norm: the planner as of b48f3c0250,
// copied below (comments dropped), must give the same plan as the current one on random batches.

// ---- reference: buildBatchPlan before the rewrite ----
const stableStringify = (value: any): string => {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(value[k])}`).join(',')}}`;
};
const AUTO_CREATED_REF_PREFIXES = ['label--', 'external-reference--', 'kill-chain-phase--', 'vocabulary--'];
const isAutoCreatedRef = (id: string): boolean => AUTO_CREATED_REF_PREFIXES.some((prefix) => id.startsWith(prefix));

const hardDependencyIds = (intent: SequencerIntent): string[] => {
  const own = new Set(intentOwnIds(intent));
  return intentEndpointIds(intent).filter((id) => !own.has(id));
};

const softDependencyIds = (intent: SequencerIntent): string[] => {
  const own = new Set(intentOwnIds(intent));
  const endpoints = new Set(intentEndpointIds(intent));
  return intent.referencedIds.filter((id) => typeof id === 'string' && id.length > 0 && !own.has(id) && !endpoints.has(id));
};
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
  foldEligible: boolean;
  resolvedTarget: boolean;
}
type MissingClass = 'queued_producer' | 'member_wait' | 'member_dead' | 'external';
const classifyMissing = (intent: SequencerIntent, id: string, options: BatchPlanOptions): MissingClass => {
  if (options.queueHas?.(id)) return 'queued_producer';
  if (!intent.memberRefIds?.has(id)) return 'external';
  if ((intent.memberWaitAttempts ?? 0) >= (options.memberWaitLimit ?? 2)) return 'member_dead';
  return 'member_wait';
};

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

const buildBatchPlanOld = (
  batch: SequencerIntent[],
  resolveId: (id: string) => string | null,
  forceDirect: Set<string> = new Set(),
  options: BatchPlanOptions = {},
): BatchPlan => {
  const chainsByKey = new Map<string, Chain>();
  const deferred: { intent: SequencerIntent; reason: DeferReason; waitingOn?: string[] }[] = [];
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
      let reason: DeferReason;
      if (intent.kind !== 'entity') reason = 'relation';
      else if (forceDirect.has(intent.id)) reason = 'force_direct';
      else if (!isFoldable(intent)) reason = 'self_not_foldable';
      else if (!chain.resolvedTarget) reason = 'unresolved_target';
      else reason = 'head_not_foldable';
      deferred.push({ intent, reason });
    }
  });
  const groups: ChainStep[] = [];
  const chainPrev: number[] = [];
  chainsByKey.forEach((chain) => {
    chain.steps.forEach((step, stepIndex) => {
      groups.push(step);
      chainPrev.push(stepIndex === 0 ? -1 : groups.length - 2);
    });
  });
  // task 0040 rule, carried into the reference: an intent deferred above is an in-flight producer
  const deferredOwnIds = new Set(deferred.flatMap(({ intent }) => intentOwnIds(intent)));
  const inFlight = (id: string) => deferredOwnIds.has(id) || (options.queueHas?.(id) ?? false);
  const planOptions: BatchPlanOptions = { ...options, queueHas: inFlight };
  const producers = new Map<string, number>();
  groups.forEach((group, index) => {
    intentOwnIds(group.leader).forEach((id) => {
      if (!producers.has(id)) producers.set(id, index);
    });
  });
  const parked: { intent: SequencerIntent; missing: string[] }[] = [];
  const finalMissing: { intent: SequencerIntent; missing: string[] }[] = [];
  const strippedDead: { intent: SequencerIntent; stripped: string[] }[] = [];
  const edges: Set<number>[] = groups.map(() => new Set());
  const applicable: boolean[] = groups.map(() => true);
  const missingByGroup = new Map<number, string[]>();
  const groupClass = new Map<number, 'parked' | 'defer' | 'final'>();
  const deferReasonByGroup = new Map<number, DeferReason>();
  const waitingByGroup = new Map<number, string[]>();
  groups.forEach((group, index) => {
    if (forceDirect.has(group.leader.id)) return;
    if (chainPrev[index] >= 0) edges[index].add(chainPrev[index]);
    const parkIds: string[] = [];
    const finalIds: string[] = [];
    const deadSoftIds: string[] = [];
    let defer: DeferReason | null = null;
    const onMissing = (id: string, soft: boolean) => {
      const cls = classifyMissing(group.leader, id, planOptions);
      if (cls === 'member_wait') {
        defer = 'member_wait';
      } else if (cls === 'queued_producer') {
        defer = defer ?? 'queued_producer';
        const waiting = waitingByGroup.get(index);
        if (waiting) {
          waiting.push(id);
        } else {
          waitingByGroup.set(index, [id]);
        }
      } else if (cls === 'member_dead') {
        if (soft) deadSoftIds.push(id);
        else if (group.leader.context?.deferMissingRefs) finalIds.push(id);
        else parkIds.push(id);
      } else if (!soft) {
        parkIds.push(id);
      } else if (options.parkSoftRefs) {
        parkIds.push(id);
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
        edges[index].add(producer);
      } else if (producer === undefined) {
        const producerInFlight = inFlight(id) || group.leader.memberRefIds?.has(id);
        if (!isAutoCreatedRef(id) || producerInFlight) onMissing(id, true);
      }
    });
    if (finalIds.length === 0 && deadSoftIds.length > 0) {
      const dead = new Set(deadSoftIds);
      [group.leader, ...group.absorbed].forEach((intent) => {
        stripDeadFromIntent(intent, dead);
        strippedDead.push({ intent, stripped: deadSoftIds });
      });
    }
    if (finalIds.length > 0) {
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
    const cls = groupClass.get(index) ?? 'parked';
    if (cls === 'final') {
      finalMissing.push({ intent: group.leader, missing });
      group.absorbed.forEach((a) => finalMissing.push({ intent: a, missing }));
    } else if (cls === 'defer') {
      const reason = deferReasonByGroup.get(index) as DeferReason;
      const waitingOn = reason === 'queued_producer' ? waitingByGroup.get(index) : undefined;
      deferred.push({ intent: group.leader, reason, waitingOn });
      group.absorbed.forEach((a) => deferred.push({ intent: a, reason, waitingOn }));
    } else {
      parked.push({ intent: group.leader, missing });
      group.absorbed.forEach((a) => parked.push({ intent: a, missing }));
    }
  });
  const priority = (index: number) => {
    const { leader } = groups[index];
    return [classifyPhase(leader), leader.arrivedAt, index] as const;
  };
  const remaining = new Set<number>(groups.map((_, i) => i).filter((i) => applicable[i]));
  const done = new Set<number>();
  const order: CoalesceGroup[] = [];
  const orderPosition = new Map<number, number>();
  while (remaining.size > 0) {
    const ready = Array.from(remaining)
      .filter((i) => Array.from(edges[i]).every((dep) => done.has(dep) || !applicable[dep]));
    const pool = ready.length > 0 ? ready : Array.from(remaining);
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
    const dependsOn = Array.from(edges[next])
      .filter((dep) => applicable[dep] && orderPosition.has(dep))
      .map((dep) => orderPosition.get(dep) as number);
    orderPosition.set(next, order.length);
    order.push({ leader: groups[next].leader, absorbed: groups[next].absorbed, dependsOn });
  }
  return { order, deferred, parked, finalMissing, strippedDead, chainedSteps };
};

// ---- random batches (seeded, rebuilt per planner: the planner mutates its intents) ----
const lcg = (seed: number) => {
  let s = seed;
  return () => {
    s = (s * 1103515245 + 12345) & 0x7fffffff;
    return s / 0x7fffffff;
  };
};

interface Scenario {
  batch: SequencerIntent[];
  resolveId: (id: string) => string | null;
  forceDirect: Set<string>;
  options: BatchPlanOptions;
}

const scenario = (seed: number): Scenario => {
  const rnd = lcg(seed);
  const pick = <T>(values: T[]): T => values[Math.floor(rnd() * values.length)];
  const n = 1 + Math.floor(rnd() * 90);
  const targets = 1 + Math.floor(rnd() * Math.max(1, n / 2));
  const tie = 1 + Math.floor(rnd() * 50);
  const entityIds = Array.from({ length: targets }, (_, k) => `malware--s${k}`);
  const relationIds = Array.from({ length: n }, (_, k) => `relationship--${k}`);
  const pool = () => {
    const r = rnd();
    if (r < 0.6) return pick(entityIds);
    if (r < 0.75) return pick(relationIds);
    if (r < 0.85) return `label--${Math.floor(rnd() * 4)}`;
    if (r < 0.92) return `report--${Math.floor(rnd() * targets)}`;
    return `identity--ext${Math.floor(rnd() * 5)}`;
  };
  const batch: SequencerIntent[] = [];
  for (let i = 0; i < n; i += 1) {
    const r = rnd();
    const base: any = {
      id: `intent-${i}`,
      user: { id: 'u' },
      opts: rnd() < 0.05 ? { references: ['ref'] } : {},
      context: { eventId: rnd() < 0.05 ? 'evt' : undefined, deferMissingRefs: rnd() < 0.5 },
      arrivedAt: 1000 + Math.floor((i + rnd() * 30) / tie),
      source: 's',
      sizeBytes: 1,
    };
    const refs = Array.from({ length: Math.floor(rnd() * 4) }, pool);
    if (r < 0.55) {
      const k = Math.floor(rnd() * targets);
      batch.push({
        ...base,
        kind: 'entity',
        type: 'Malware',
        input: { name: `m${k}`, confidence: pick([50, 75]), objectLabel: refs.filter((id) => id.startsWith('label--')), createdBy: pick([null, ...refs]) },
        candidateIds: rnd() < 0.05 ? [] : [`malware--s${k}`, `malware--x${k}-${Math.floor(rnd() * 2)}`],
        referencedIds: refs,
        memberRefIds: rnd() < 0.4 ? new Set(refs.filter(() => rnd() < 0.5)) : undefined,
        memberWaitAttempts: Math.floor(rnd() * 3),
      });
    } else if (r < 0.68) {
      // container: its members may all be dead soft refs, the strip then empties objects (phase 2 -> 0)
      const k = Math.floor(rnd() * targets);
      const objects = Array.from({ length: Math.floor(rnd() * 4) }, () => (rnd() < 0.5 ? `dead--${Math.floor(rnd() * 3)}` : pool()));
      batch.push({
        ...base,
        kind: 'entity',
        type: 'Report',
        input: { name: `r${k}`, objects },
        candidateIds: [`report--${k}`],
        referencedIds: [...objects, ...refs],
        memberRefIds: new Set(objects.filter(() => rnd() < 0.8)),
        memberWaitAttempts: Math.floor(rnd() * 4),
      });
    } else {
      const fromId = pool();
      const toId = rnd() < 0.1 ? pick(relationIds) : pool();
      batch.push({
        ...base,
        kind: 'relation',
        type: pick(['uses', 'indicates']),
        input: { fromId, toId, relationship_type: 'uses', description: pick(['a', 'b']) },
        candidateIds: [`relationship--${i}`, fromId, toId],
        referencedIds: [fromId, toId, ...refs],
        memberRefIds: rnd() < 0.3 ? new Set([fromId, toId].filter(() => rnd() < 0.5)) : undefined,
        memberWaitAttempts: Math.floor(rnd() * 3),
      });
    }
  }
  const resolved = new Set([...entityIds, ...relationIds, 'label--0', 'identity--ext0'].filter(() => rnd() < 0.3));
  const queued = new Set([...entityIds, ...relationIds, 'label--1', 'dead--0', 'identity--ext1'].filter(() => rnd() < 0.15));
  const forceDirect = new Set(batch.filter(() => rnd() < 0.05).map((intent) => intent.id));
  const options: BatchPlanOptions = {
    parkSoftRefs: rnd() < 0.5,
    queueHas: rnd() < 0.8 ? (id) => queued.has(id) : undefined,
    memberWaitLimit: 1 + Math.floor(rnd() * 3),
  };
  return { batch, resolveId: (id) => (resolved.has(id) ? `int-${id}` : null), forceDirect, options };
};

// plan and mutated intents as plain data, intents by id
const shapeOf = (plan: BatchPlan, batch: SequencerIntent[]) => JSON.stringify({
  order: plan.order.map((g) => [g.leader.id, g.absorbed.map((a) => a.id), g.dependsOn]),
  deferred: plan.deferred.map((d) => [d.intent.id, d.reason, d.waitingOn]),
  parked: plan.parked.map((p) => [p.intent.id, p.missing]),
  finalMissing: plan.finalMissing.map((p) => [p.intent.id, p.missing]),
  strippedDead: plan.strippedDead.map((p) => [p.intent.id, p.stripped]),
  chainedSteps: plan.chainedSteps,
  intents: batch.map((i) => [i.input, i.referencedIds, i.memberRefIds ? [...i.memberRefIds] : null, i.memberWaitAttempts, i.deadStrippedRefs]),
});

const planBoth = (seed: number) => {
  const a = scenario(seed);
  const b = scenario(seed);
  return {
    expected: shapeOf(buildBatchPlanOld(a.batch, a.resolveId, a.forceDirect, a.options), a.batch),
    actual: shapeOf(buildBatchPlan(b.batch, b.resolveId, b.forceDirect, b.options), b.batch),
  };
};

// ---- reference: step 4 alone (bench-topo.mjs orderOld) ----
const orderOld = (groups: { leader: SequencerIntent; absorbed: SequencerIntent[] }[], edges: Set<number>[], applicable: boolean[]) => {
  const priority = (index: number) => {
    const { leader } = groups[index];
    return [classifyPhase(leader), leader.arrivedAt, index] as const;
  };
  const remaining = new Set<number>(groups.map((_, i) => i).filter((i) => applicable[i]));
  const done = new Set<number>();
  const order: CoalesceGroup[] = [];
  const orderPosition = new Map<number, number>();
  while (remaining.size > 0) {
    const ready = Array.from(remaining)
      .filter((i) => Array.from(edges[i]).every((dep) => done.has(dep) || !applicable[dep]));
    const pool = ready.length > 0 ? ready : Array.from(remaining);
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
    const dependsOn = Array.from(edges[next])
      .filter((dep) => applicable[dep] && orderPosition.has(dep))
      .map((dep) => orderPosition.get(dep) as number);
    orderPosition.set(next, order.length);
    order.push({ leader: groups[next].leader, absorbed: groups[next].absorbed, dependsOn });
  }
  return order;
};

// bench-topo.mjs makeBatch: round-robin arrivals with ties, a few back edges (cycles), non-applicable groups
const topoBatch = (seed: number) => {
  const rnd = lcg(seed);
  const n = 1 + Math.floor(rnd() * 120);
  const cycles = rnd() * 0.6;
  const nonApplicable = rnd() * 0.4;
  const tieMs = 1 + Math.floor(rnd() * 1000);
  const groups: { leader: SequencerIntent; absorbed: SequencerIntent[] }[] = [];
  for (let i = 0; i < n; i += 1) {
    const r = rnd();
    const arrivedAt = 1_700_000_000_000 + Math.floor((i + Math.floor(rnd() * 60)) / tieMs);
    let leader: any;
    if (r < 0.55) leader = { kind: 'entity', input: { name: `e${i}` }, arrivedAt };
    else if (r < 0.62) leader = { kind: 'entity', input: { objects: ['x', 'y'] }, arrivedAt };
    else if (r < 0.97) leader = { kind: 'relation', input: { fromId: `indicator--${i}`, toId: `malware--${i}` }, arrivedAt };
    else leader = { kind: 'relation', input: { fromId: `relationship--${i}`, toId: `malware--${i}` }, arrivedAt };
    groups.push({ leader, absorbed: [] });
  }
  const edges = groups.map(() => new Set<number>());
  for (let i = 0; i < n; i += 1) {
    const { leader } = groups[i];
    const nDeps = leader.kind === 'relation' ? 2 : (leader.input.objects ? Math.floor(rnd() * 40) : (rnd() < 0.3 ? 1 : 0));
    for (let k = 0; k < nDeps; k += 1) {
      const dep = Math.floor(rnd() * n);
      if (dep !== i && (dep < i || rnd() < cycles)) edges[i].add(dep);
    }
  }
  const applicable = groups.map(() => rnd() >= nonApplicable);
  return { groups, edges, applicable };
};

const orderShape = (order: CoalesceGroup[]) => order.map((g) => [g.leader, g.dependsOn]);

describe('sequencer batch plan oracle (Kahn order, lazy norm)', () => {
  it('step 4 orders exactly as the former loop on 3,000 random graphs (cycles, ties, non-applicable)', () => {
    for (let seed = 1; seed <= 3000; seed += 1) {
      const { groups, edges, applicable } = topoBatch(seed);
      expect(orderShape(orderApplicable(groups, edges, applicable)), `seed ${seed}`).toEqual(orderShape(orderOld(groups, edges, applicable)));
    }
  });

  it('breaks cycles by the lowest (phase, arrival, index) and never emits a node twice', () => {
    const leader = (arrivedAt: number, input: any = {}): any => ({ kind: 'entity', input, arrivedAt });
    // 0 <-> 1 cycle, 2 depends on 1, 3 independent container, 4 self loop, 5 non-applicable dep of 2
    const groups = [leader(5), leader(3), leader(1), leader(0, { objects: ['x'] }), leader(3), leader(0)].map((l) => ({ leader: l, absorbed: [] }));
    const edges = [new Set([1]), new Set([0]), new Set([1, 5]), new Set<number>(), new Set([4]), new Set<number>()];
    const applicable = [true, true, true, true, true, false];
    const order = orderApplicable(groups, edges, applicable);
    expect(orderShape(order)).toEqual(orderShape(orderOld(groups, edges, applicable)));
    // 3 is the only ready node; then a cycle break takes 2 (lowest arrival), 1 (arrival 3, index
    // 1), and 0 becomes ready; 4 (self loop) last; a forward edge is omitted from dependsOn
    expect(order.map((g) => groups.findIndex((x) => x.leader === g.leader))).toEqual([3, 2, 1, 0, 4]);
    expect(order.map((g) => g.dependsOn)).toEqual([[], [], [], [2], []]);
    expect(orderApplicable([], [], [])).toEqual([]);
  });

  it('whole plan identical to the former planner on 3,000 random batches', () => {
    let ordered = 0;
    let stripped = 0;
    for (let seed = 1; seed <= 3000; seed += 1) {
      const { expected, actual } = planBoth(seed);
      expect(actual, `seed ${seed}`).toBe(expected);
      const parsed = JSON.parse(expected);
      ordered += parsed.order.length;
      stripped += parsed.strippedDead.length;
    }
    // the generator reaches the paths it is meant to cover
    expect(ordered).toBeGreaterThan(10000);
    expect(stripped).toBeGreaterThan(100);
  });

  it('orders a container emptied by the dead strip as phase 0, as the former planner did', () => {
    const intent = (id: string, arrivedAt: number, extra: any): SequencerIntent => ({
      id, user: { id: 'u' }, opts: {}, context: {}, arrivedAt, source: 's', sizeBytes: 1, referencedIds: [], ...extra,
    } as any);
    const build = () => [
      intent('rel', 1, { kind: 'relation', type: 'uses', input: { fromId: 'malware--ok', toId: 'identity--ok' }, candidateIds: ['relationship--r'] }),
      intent('report', 2, { kind: 'entity', type: 'Report', input: { objects: ['malware--gone'] }, candidateIds: ['report--1'], referencedIds: ['malware--gone'], memberRefIds: new Set(['malware--gone']), memberWaitAttempts: 2 }),
    ];
    const resolveId = (id: string) => (id.endsWith('--ok') ? id : null);
    const a = build();
    const b = build();
    const plan = buildBatchPlan(b, resolveId);
    expect(shapeOf(plan, b)).toBe(shapeOf(buildBatchPlanOld(a, resolveId), a));
    // stripped to no member: phase 0, before the phase-1 relation despite arriving later
    expect(b[1].input.objects).toEqual([]);
    expect(plan.order.map((g) => g.leader.id)).toEqual(['report', 'rel']);
  });

  it('coalesces on the normalized input only among same-key intents (key order does not matter)', () => {
    const intent = (id: string, input: any, candidateIds: string[]): SequencerIntent => ({
      id, kind: 'entity', type: 'Malware', input, user: { id: 'u' }, opts: {}, context: {}, arrivedAt: 1, source: 's', sizeBytes: 1, candidateIds, referencedIds: [],
    } as any);
    const build = () => [
      intent('a', { name: 'x', confidence: 1 }, ['malware--1']),
      intent('b', { confidence: 1, name: 'x' }, ['malware--1']),
      intent('c', { name: 'x', confidence: 2 }, ['malware--1']),
      intent('d', { name: 'x', confidence: 1 }, ['malware--2']),
      intent('e', { name: 'x', confidence: 2 }, ['malware--1']),
    ];
    const resolveId = (id: string) => (id === 'malware--1' ? 'int-1' : null);
    const a = build();
    const b = build();
    const plan = buildBatchPlan(b, resolveId);
    expect(shapeOf(plan, b)).toBe(shapeOf(buildBatchPlanOld(a, resolveId), a));
    expect(plan.order.map((g) => [g.leader.id, g.absorbed.map((x) => x.id)])).toEqual([['a', ['b']], ['c', ['e']], ['d', []]]);
    expect(plan.chainedSteps).toBe(1);
  });
});
