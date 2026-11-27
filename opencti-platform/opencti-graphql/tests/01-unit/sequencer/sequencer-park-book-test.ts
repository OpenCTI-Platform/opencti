import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { buildBatchPlan, canonicalKey } from '../../../src/database/sequencer/sequencer-batch-plan';
import { buildIntent, intentEndpointIds, intentOwnIds } from '../../../src/database/sequencer/sequencer-intent';
import type { SequencerIntent } from '../../../src/database/sequencer/sequencer-intent';
import { DeferredLanes } from '../../../src/database/sequencer/sequencer-lanes';
import { ParkBook } from '../../../src/database/sequencer/sequencer-park-book';
import { SEQUENCER_CONFIG } from '../../../src/database/sequencer/sequencer-config';
import type { AuthContext, AuthUser } from '../../../src/types/user';

// task 0040 lead 36: each intent waits at most one park deadline for a missing reference, whatever path brings it
// back into a batch, and the loop never re-plans a parked set with nothing new. The harness below runs the cycle of
// sequencer-loop.ts around the real planner, lanes and park book, on a simulated clock: lanes first (one ready head
// per key), then (when nothing at all is pending) a wait for the next arrival or the nearest deadline, the parked
// set, the queue; expiry, plan, deferrals to the lanes, park routing, apply. An apply succeeds when the endpoints of
// the relation exist at that time; an entity apply makes its own ids exist.

const DEADLINE = 5000;
const CYCLE = 10;

let arrival = 0;
const relationOf = (user: string, extra: { description?: string; context?: Record<string, any> } = {}) => {
  const intent = buildIntent({
    kind: 'relation',
    type: 'uses',
    input: { fromId: 'malware--a', toId: 'attack-pattern--b', ...(extra.description ? { description: extra.description } : {}) },
    user: { id: user, origin: { applicant_id: user } } as unknown as AuthUser,
    context: (extra.context ?? {}) as unknown as AuthContext,
    opts: {},
    candidateIds: ['relationship--stix', 'malware--a', 'attack-pattern--b'],
    referencedIds: [],
    apply: async () => null,
  });
  arrival += 1;
  (intent as any).arrivedAt = arrival;
  return intent;
};
const producerOf = (id: string) => {
  const intent = buildIntent({
    kind: 'entity',
    type: 'Attack-Pattern',
    input: { name: id },
    user: { id: 'mitre', origin: {} } as unknown as AuthUser,
    context: {} as unknown as AuthContext,
    opts: {},
    candidateIds: [id],
    referencedIds: [],
    apply: async () => null,
  });
  arrival += 1;
  (intent as any).arrivedAt = arrival;
  return intent;
};

const lcg = (seed: number) => {
  let state = seed;
  return () => {
    state = (state * 1103515245 + 12345) & 0x7fffffff;
    return state / 0x7fffffff;
  };
};

const intentFor = (kind: 'entity' | 'relation', type: string, input: Record<string, any>, candidateIds: string[], user: string, referencedIds: string[] = [], memberRefIds?: Set<string>) => {
  const intent = buildIntent({
    kind,
    type,
    input,
    user: { id: user, origin: { applicant_id: user } } as unknown as AuthUser,
    context: {} as unknown as AuthContext,
    opts: {},
    candidateIds,
    referencedIds,
    memberRefIds,
    apply: async () => null,
  });
  arrival += 1;
  (intent as any).arrivedAt = arrival;
  return intent;
};
const usesOf = (to: string, user: string, extra: { stix?: string; description?: string; createdBy?: string } = {}) => intentFor(
  'relation',
  'uses',
  { fromId: 'malware--a', toId: to, ...(extra.description ? { description: extra.description } : {}), ...(extra.createdBy ? { createdBy: extra.createdBy } : {}) },
  [extra.stix ?? `relationship--${to}`, 'malware--a', to],
  user,
  extra.createdBy ? [extra.createdBy] : [],
);
const reportOf = (id: string, user: string, objects: string[], members?: string[]) => intentFor('entity', 'Report', { name: id, objects }, [id], user, objects, members ? new Set(members) : undefined);

interface Run {
  arrivals: { at: number; intent: SequencerIntent }[];
  // producers visible in the queue from `at` (batch cap pressure: queued, not yet in a batch)
  queued?: { id: string; at: number }[];
  // apply of a relation fails on a missing reference although the plan saw its endpoints (identity map gap)
  applyFails?: boolean;
  parkSoftRefs?: boolean;
  // intents whose first planned apply at or after `at` is carried to the next batch (multi_writer lock retry)
  carries?: { id: string; at: number }[];
  untilMs?: number;
  // debugging aid: one line per cycle
  trace?: (line: string) => void;
}

const LANE_ADMIT_CAP = Math.max(1, Math.floor(SEQUENCER_CONFIG.maxBatchSize * SEQUENCER_CONFIG.deferredReadmitRatio));
const FAILED_PRODUCER_DEFER_LIMIT = 2; // sequencer-loop.ts processGroup
const RESIDUAL = new Set(['relation', 'unresolved_target', 'self_not_foldable', 'head_not_foldable']);

// The cycle of sequencer-loop.ts: lanes and carried intents first; when nothing at all is pending, a wait for the
// next arrival (into the batch or the queue) or the nearest park deadline, that arrival first; the parked set; the
// rest of the queue. Then expiry, plan, deferrals to the lanes, park routing, apply in plan order: a group behind a
// producer that failed in this batch goes to its lane (failed_producer, twice at most), a carry (lock retry), a
// success, or a failure with its park when parkSoftRefs is on.
// Progress events: an arrival, a queued producer appearing, an apply, a failure, a fresh park, an expiry, a lane
// wake, a carry, a member wait pass, a failed-producer deferral. A cycle without any is a stateless re-plan; moves
// between the parked set and the lanes are not progress (that is how the park / lane alternation hid), and each
// intent's park -> lane -> park round trips are counted (concurrent traffic hides a stateless count).
// Park time is summed per clock: from a park (fresh or kept) to leaving it (apply, lane, expiry, failure).
const simulate = (run: Run) => {
  const book = new ParkBook(DEADLINE);
  const lanes = new DeferredLanes();
  const exists = new Set(['malware--a']);
  // applyFails: the identity map resolves everything, the apply does not find the endpoint
  const resolveId = (id: string) => (run.applyFails || exists.has(id) ? `int-${id}` : null);
  const ids = run.arrivals.map(({ intent }) => intent.id);
  const freshParks = new Map<string, number>(ids.map((id) => [id, 0]));
  const restarts = new Map<string, number>(ids.map((id) => [id, 0]));
  const inPark = new Map<string, number>();
  const clockPark = new Map<string, number>(); // park time of the current clock
  let maxParkWait = 0;
  const expiredOutsidePark: string[] = [];
  const leftToLane = new Set<string>();
  const roundTrips = new Map<string, number>();
  const settled = new Map<string, { at: number; outcome: 'applied' | 'failed'; forced: boolean }>();
  const carries = [...(run.carries ?? [])];
  let carried: SequencerIntent[] = [];
  let pending = [...run.arrivals].sort((a, b) => a.at - b.at);
  // arrival rank (time, then listing order) and apply step of each intent: same-key writes must apply in arrival order
  const arrivalRank = new Map<string, number>(pending.map(({ intent }, rank) => [intent.id, rank]));
  const applyStep = new Map<string, number>();
  let steps = 0;
  let now = 0;
  let cycles = 0;
  let laneTrips = 0;
  let statelessReplans = 0;
  const openPark = (intent: SequencerIntent) => {
    if (!inPark.has(intent.id)) inPark.set(intent.id, now);
  };
  const closePark = (intent: SequencerIntent) => {
    const since = inPark.get(intent.id);
    if (since === undefined) return;
    inPark.delete(intent.id);
    const total = (clockPark.get(intent.id) ?? 0) + now - since;
    clockPark.set(intent.id, total);
    maxParkWait = Math.max(maxParkWait, total);
  };
  const countParks = (intents: SequencerIntent[]) => intents.forEach((intent) => {
    freshParks.set(intent.id, (freshParks.get(intent.id) ?? 0) + 1);
    clockPark.set(intent.id, 0);
  });
  const settle = (intent: SequencerIntent, outcome: 'applied' | 'failed', forced: boolean) => {
    closePark(intent);
    settled.set(intent.id, { at: now, outcome, forced });
  };
  const queuedNow = (id: string) => (run.queued ?? []).some((q) => q.id === id && q.at <= now && !exists.has(id));
  const queuePressure = () => (run.queued ?? []).some((q) => q.at <= now && !exists.has(q.id));
  const untilMs = run.untilMs ?? 120_000;
  while (settled.size < ids.length && now <= untilMs) {
    cycles += 1;
    let progress = false;
    vi.setSystemTime(now);
    const admission = lanes.admit(LANE_ADMIT_CAP, now);
    laneTrips += admission.intents.length;
    const batch: SequencerIntent[] = [...admission.intents, ...carried];
    if (carried.length > 0) progress = true;
    carried = [];
    const due = () => {
      const arrived = pending.filter((a) => a.at <= now).map((a) => {
        a.intent.arrivedAt = a.at; // as the intake stamps it (buildIntent)
        return a.intent;
      });
      pending = pending.filter((a) => a.at > now);
      return arrived;
    };
    let arrived: SequencerIntent[] = [];
    if (batch.length === 0 && !pending.some((a) => a.at <= now) && !queuePressure()) {
      const nearest = book.nearestDeadline();
      const upcoming = [...pending.map((a) => a.at), ...(run.queued ?? []).map((q) => q.at)].filter((at) => at > now);
      const next = upcoming.length > 0 ? Math.min(...upcoming) : null;
      if (nearest === null && next === null) break;
      now = Math.max(now + 1, Math.min(nearest ?? Infinity, next ?? Infinity));
      vi.setSystemTime(now);
      const first = due();
      batch.push(...first.slice(0, 1)); // the awaited arrival comes before the parked set
      arrived = first.slice(1);
      if (first.length > 0 || (run.queued ?? []).some((q) => q.at === now)) progress = true;
    }
    const taken = new Set(book.take().map((intent) => {
      batch.push(intent);
      return intent.id;
    }));
    const rest = due();
    if (rest.length > 0) progress = true;
    batch.push(...arrived, ...rest);
    const { forceDirect, newlyExpired } = book.expire(batch, new Set(admission.exhausted.map((i) => i.id)), now);
    newlyExpired.forEach(({ intent }) => {
      progress = true;
      if (!taken.has(intent.id)) expiredOutsidePark.push(intent.id);
      closePark(intent);
    });
    const plan = buildBatchPlan(batch, resolveId, forceDirect, {
      parkSoftRefs: run.parkSoftRefs ?? false,
      queueHas: (id) => queuedNow(id) || lanes.hasResident(id),
    });
    plan.deferred.forEach(({ intent, reason, waitingOn }) => {
      if ((reason === 'queued_producer' || reason === 'member_wait') && intent.parkDeadline !== undefined) {
        restarts.set(intent.id, (restarts.get(intent.id) ?? 0) + 1);
        closePark(intent);
        clockPark.delete(intent.id);
      }
      if (reason === 'member_wait') progress = true; // a pass counted on the intent
      if (RESIDUAL.has(reason) && taken.has(intent.id)) leftToLane.add(intent.id);
      lanes.defer(canonicalKey(intent, resolveId), intent, waitingOn);
    });
    plan.finalMissing.forEach(({ intent }) => {
      progress = true;
      settle(intent, 'failed', false);
    });
    plan.parked.forEach(({ intent }) => {
      if (leftToLane.delete(intent.id)) roundTrips.set(intent.id, (roundTrips.get(intent.id) ?? 0) + 1);
    });
    const routing = book.route(plan, now);
    if (routing.fresh.length > 0) progress = true;
    countParks(routing.fresh);
    plan.parked.forEach(({ intent }) => openPark(intent));
    // the park wait ends when the intent leaves it (to apply, or to its lane): a lane or a lock wait is not a park wait
    routing.unparked.forEach(({ intent }) => closePark(intent));
    const failedAt: boolean[] = [];
    plan.order.forEach(({ leader, absorbed, dependsOn }, position) => {
      const group = [leader, ...absorbed];
      if ((dependsOn ?? []).some((d) => failedAt[d]) && (leader.failedProducerDefers ?? 0) < FAILED_PRODUCER_DEFER_LIMIT) {
        leader.failedProducerDefers = (leader.failedProducerDefers ?? 0) + 1;
        failedAt[position] = true;
        progress = true;
        group.forEach((intent) => lanes.defer(canonicalKey(intent, resolveId), intent));
        return;
      }
      const carry = carries.findIndex((c) => c.at <= now && group.some((intent) => intent.id === c.id));
      if (carry >= 0) {
        carries.splice(carry, 1);
        carried.push(...group);
        failedAt[position] = true;
        progress = true;
        return;
      }
      progress = true;
      const missing = leader.kind === 'relation' && (run.applyFails || intentEndpointIds(leader).some((id) => !exists.has(id)));
      if (missing) {
        failedAt[position] = true;
        if ((run.parkSoftRefs ?? false) && !forceDirect.has(leader.id)) {
          const { parked, fresh } = book.parkAfterFailure(leader, absorbed, now);
          countParks(fresh);
          if (parked) {
            group.forEach((intent) => openPark(intent));
            return;
          }
        }
        group.forEach((intent) => settle(intent, 'failed', forceDirect.has(intent.id)));
        lanes.wake(group.flatMap((intent) => intentOwnIds(intent)), 'failed');
        return;
      }
      steps += 1;
      group.forEach((intent) => {
        intentOwnIds(intent).forEach((id) => exists.add(id));
        applyStep.set(intent.id, steps);
        settle(intent, 'applied', forceDirect.has(intent.id));
      });
      lanes.wake(group.flatMap((intent) => intentOwnIds(intent)), 'landed');
    });
    if (!progress && !queuePressure()) statelessReplans += 1;
    if (run.trace) {
      const name = (intent: SequencerIntent) => `${intent.type}/${(intent.user as any).id}#${ids.indexOf(intent.id)}${intent.expired ? '!' : ''}`;
      run.trace(`t=${now} ${progress ? '' : 'STATELESS '}batch=[${batch.map(name)}] order=[${plan.order.map((g) => [g.leader, ...g.absorbed].map(name).join('+'))}] parked=[${plan.parked.map((p) => name(p.intent))}] deferred=[${plan.deferred.map((d) => `${name(d.intent)}:${d.reason}`)}] carried=[${carried.map(name)}]`);
    }
    now += CYCLE;
  }
  // same-key pairs applied out of arrival order (a newer write applied in an earlier step than an older one): asserted
  // on the lead 38 shapes only; on random shapes it is a measure (task 0050 lead 43: about half the seeds, parked
  // intents re-enter a batch in park order, the planner takes the batch position as the age)
  const byKey = new Map<string, SequencerIntent[]>();
  run.arrivals.forEach(({ intent }) => {
    if (!applyStep.has(intent.id)) return;
    const key = canonicalKey(intent, resolveId);
    byKey.set(key, [...(byKey.get(key) ?? []), intent]);
  });
  const outOfOrder: string[] = [];
  byKey.forEach((intents, key) => intents.forEach((older) => intents.forEach((newer) => {
    if ((arrivalRank.get(older.id) ?? 0) < (arrivalRank.get(newer.id) ?? 0) && (applyStep.get(older.id) ?? 0) > (applyStep.get(newer.id) ?? 0)) {
      outOfOrder.push(`${key}: #${ids.indexOf(newer.id)} before #${ids.indexOf(older.id)}`);
    }
  })));
  return {
    outOfOrder,
    parks: ids.map((id) => freshParks.get(id)),
    restarts: ids.map((id) => restarts.get(id)),
    maxParkWait,
    maxRoundTrips: Math.max(0, ...roundTrips.values()),
    settled: ids.map((id) => settled.get(id)),
    unsettled: ids.filter((id) => !settled.has(id)),
    expiredOutsidePark,
    cycles,
    laneTrips,
    statelessReplans,
  };
};

// What every run must hold (I4): settled; at most one deadline of park time per clock; parks <= 1 + clock restarts;
// never forced by a deadline outside a park; at most one park -> lane -> park round trip per intent (a companion
// whose head or producer applied, then failed); stateless re-plans bounded by the intents.
const liveProblems = (run: ReturnType<typeof simulate>): string[] => {
  const problems: string[] = [];
  if (run.unsettled.length > 0) problems.push(`unsettled ${run.unsettled.length}`);
  if (run.maxParkWait > DEADLINE + 3 * CYCLE) problems.push(`park wait ${run.maxParkWait}`);
  if (run.statelessReplans > run.parks.length) problems.push(`stateless re-plans ${run.statelessReplans}`);
  if (run.expiredOutsidePark.length > 0) problems.push(`expired outside a park ${run.expiredOutsidePark.length}`);
  if (run.maxRoundTrips > 1) problems.push(`round trips ${run.maxRoundTrips}`);
  run.parks.forEach((parks, i) => {
    if ((parks ?? 0) > 1 + (run.restarts[i] ?? 0)) problems.push(`parks ${parks} restarts ${run.restarts[i]}`);
  });
  return problems;
};
const expectLive = (run: ReturnType<typeof simulate>) => expect(liveProblems(run)).toEqual([]);

const staggered = (count: number, everyMs: number, of: (k: number) => SequencerIntent) => Array.from({ length: count }, (_, k) => ({ at: k * everyMs, intent: of(k) }));

describe('park book: one park deadline per intent, whatever path brings it back (task 0040 lead 36)', () => {
  beforeEach(() => {
    vi.useFakeTimers({ now: 0 });
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  // the review 2026-11-25 cases: a parked companion sent to its lane when its head left got a fresh deadline back
  it.each([
    ['two connectors 1 s apart', staggered(2, 1000, (k) => relationOf(`c${k}`))],
    ['four connectors 1 s apart', staggered(4, 1000, (k) => relationOf(`c${k}`))],
    ['twenty connectors 1 s apart', staggered(20, 1000, (k) => relationOf(`c${k}`))],
    ['one connector, twenty descriptions 1 s apart', staggered(20, 1000, (k) => relationOf('c', { description: `d${k}` }))],
    ['all at once', staggered(3, 0, (k) => relationOf(`c${k}`))],
  ])('%s, the endpoint never lands: each parks once, gives up at its deadline, no idle re-plan', (_, arrivals) => {
    const run = simulate({ arrivals });
    expectLive(run);
    expect(run.parks).toEqual(arrivals.map(() => 1));
    expect(run.settled.map((s) => s?.outcome)).toEqual(arrivals.map(() => 'failed'));
  });

  it('applies every relation when the endpoint lands within the deadline', () => {
    const arrivals = [...staggered(3, 1000, (k) => relationOf(`c${k}`)), { at: 3500, intent: producerOf('attack-pattern--b') }];
    const run = simulate({ arrivals });
    expect(run.settled.map((s) => s?.outcome)).toEqual(['applied', 'applied', 'applied', 'applied']);
    run.settled.forEach((s) => expect(s?.at).toBeLessThan(3500 + 5 * CYCLE));
    expect(run.parks.slice(0, 3)).toEqual([1, 1, 1]);
    expectLive(run);
  });

  it('never absorbs an expired intent under a fresh leader: no idle re-plan past its deadline (C3)', () => {
    // x1 and x2: same connector, same input; x1 parks behind h, h leaves, x2 arrives fresh while x1 expires
    const arrivals = [{ at: 0, intent: relationOf('h') }, { at: 1000, intent: relationOf('x') }, { at: 3000, intent: relationOf('x') }];
    const run = simulate({ arrivals });
    expect(run.parks).toEqual([1, 1, 1]);
    expectLive(run);
  });

  it('apply failures on a missing reference (parkSoftRefs): bounded by the deadline of each relation', () => {
    const run = simulate({ arrivals: staggered(2, 0, (k) => relationOf(`c${k}`)), applyFails: true, parkSoftRefs: true });
    expect(run.parks).toEqual([1, 1]);
    expect(run.maxParkWait).toBeLessThanOrEqual(DEADLINE + 3 * CYCLE);
    expect(run.settled.map((s) => s?.outcome)).toEqual(['failed', 'failed']);
    // residual: the two hand the lane to each other, one failing apply per cycle until the deadline
    expect(run.cycles).toBeLessThanOrEqual(DEADLINE / CYCLE + 5);
  });

  it('restarts the clock when the producer is queued: a B10 wait is never cut at the park deadline', () => {
    // parked at 0 (producer unknown), the producer is seen queued at 4 s and lands only at 40 s (lane TTL passed once)
    const relation = relationOf('c0');
    const run = simulate({
      arrivals: [{ at: 0, intent: relation }, { at: 40_000, intent: producerOf('attack-pattern--b') }],
      queued: [{ id: 'attack-pattern--b', at: 4000 }],
    });
    expect(SEQUENCER_CONFIG.deferredWaitTtlMs).toBeLessThan(36_000);
    expect(run.settled[0]).toEqual({ at: expect.any(Number), outcome: 'applied', forced: false });
    expect(run.settled[0]?.at).toBeGreaterThanOrEqual(40_000);
    expect(run.restarts[0]).toBe(1);
  });

  // review 2026-11-25 round 5: the head parks behind an in-batch producer that parks (fixpoint), or on a shared soft
  // ref; same-key entities (reports of two connectors) behind such a head
  it.each([
    ['relations to a parked in-batch relation (fixpoint)', () => [
      { at: 0, intent: usesOf('attack-pattern--b', 'q', { stix: 'relationship--q' }) },
      { at: 0, intent: usesOf('relationship--q', 'c0') },
      { at: 0, intent: usesOf('relationship--q', 'c1') },
    ], false],
    ['reports of two connectors behind a parked in-batch relation', () => [
      { at: 0, intent: usesOf('attack-pattern--b', 'q', { stix: 'relationship--q' }) },
      { at: 0, intent: reportOf('report--r', 'c0', ['relationship--q']) },
      { at: 0, intent: reportOf('report--r', 'c1', ['relationship--q']) },
    ], false],
    ['relations parked on a shared soft ref (parkSoftRefs)', () => [
      { at: 0, intent: usesOf('attack-pattern--b', 'c0', { createdBy: 'identity--x' }) },
      { at: 0, intent: usesOf('attack-pattern--b', 'c1', { createdBy: 'identity--x' }) },
    ], true],
  ] as [string, () => { at: number; intent: SequencerIntent }[], boolean][])('%s: no park / lane alternation', (_, arrivalsOf, parkSoftRefs) => {
    const run = simulate({ arrivals: arrivalsOf(), parkSoftRefs });
    expectLive(run);
    expect(run.laneTrips).toBeLessThanOrEqual(3);
  });

  it('never forces an intent that left its park (its endpoint landed) and is carried past its old deadline (C-B)', () => {
    const relation = usesOf('attack-pattern--b', 'c0');
    const run = simulate({
      arrivals: [{ at: 0, intent: relation }, { at: DEADLINE - 2 * CYCLE, intent: producerOf('attack-pattern--b') }],
      carries: [{ id: relation.id, at: 0 }, { id: relation.id, at: 0 }, { id: relation.id, at: 0 }],
    });
    expectLive(run);
    expect(run.settled[0]).toEqual({ at: expect.any(Number), outcome: 'applied', forced: false });
  });

  it('never holds a ready intent behind a lane head waiting on a queued producer (round 6: lane head-of-line)', () => {
    // the older relation parks on b; the newer one of another connector also waits on its own queued soft ref x:
    // when b lands the newer one heads the lane waiting on x, the older one must not queue behind it
    const older = usesOf('attack-pattern--b', 'c1');
    const newer = usesOf('attack-pattern--b', 'c0', { createdBy: 'identity--x' });
    const run = simulate({
      arrivals: [{ at: 0, intent: older }, { at: 1000, intent: newer }, { at: 1000, intent: producerOf('attack-pattern--b') }, { at: 20_000, intent: producerOf('identity--x') }],
      queued: [{ id: 'identity--x', at: 1000 }],
    });
    expectLive(run);
    expect(run.settled[0]).toEqual({ at: expect.any(Number), outcome: 'applied', forced: false });
    expect(run.settled[0]?.at).toBeLessThan(1000 + 5 * CYCLE);
    expect(run.settled[1]).toEqual({ at: expect.any(Number), outcome: 'applied', forced: false });
  });

  // round 8 review shapes: two writes of one key wait on the same queued producer; both wake on its landing
  it.each([
    ['relations, the endpoint lands later (A)', 1000],
    ['relations, the endpoint lands at the next cycle (A2)', CYCLE],
  ])('applies the writes of one key in arrival order when they wait on the same queued producer: %s (lead 38)', (_, landsAt) => {
    const older = usesOf('attack-pattern--b', 'c1', { description: 'old' });
    const newer = usesOf('attack-pattern--b', 'c2', { description: 'new' });
    const run = simulate({
      arrivals: [{ at: 0, intent: older }, { at: 0, intent: newer }, { at: landsAt, intent: producerOf('attack-pattern--b') }],
      queued: [{ id: 'attack-pattern--b', at: 0 }],
    });
    expectLive(run);
    expect(run.settled.slice(0, 2).map((s) => s?.outcome)).toEqual(['applied', 'applied']);
    expect(run.outOfOrder).toEqual([]);
  });

  it('applies the entity writes of one key in arrival order when they wait on the same queued producer (lead 38, C)', () => {
    const entityOf = (description: string, context: Record<string, any>) => {
      const intent = intentFor('entity', 'Malware', { name: 'M', description, createdBy: 'identity--q' }, ['malware--a'], 'c1', ['identity--q']);
      (intent as any).context = context; // an event replay: never folded into its head's chain
      return intent;
    };
    const run = simulate({
      arrivals: [{ at: 0, intent: entityOf('old', {}) }, { at: 0, intent: entityOf('new', { eventId: 'ev-2' }) }, { at: 1000, intent: producerOf('identity--q') }],
      queued: [{ id: 'identity--q', at: 0 }],
    });
    expectLive(run);
    expect(run.settled.slice(0, 2).map((s) => s?.outcome)).toEqual(['applied', 'applied']);
    expect(run.outOfOrder).toEqual([]);
  });

  // the class, on random shapes: 1-2 keys, relations to an external endpoint or to a parked in-batch relation,
  // same-key reports, 2-5 same-key intents of 3 connectors (same norm too: C3) with or without a description,
  // staggered arrivals, endpoints that land late, never, or are seen queued first (B10), member annotations,
  // a shared soft ref under parkSoftRefs, carries
  const randomRun = (seed: number): Run => {
    const rnd = lcg(seed);
    const pick = <T>(values: T[]): T => values[Math.floor(rnd() * values.length)];
    const at = (maxMs: number) => Math.floor(rnd() * (maxMs / 100)) * 100;
    const arrivals: { at: number; intent: SequencerIntent }[] = [];
    const queued: { id: string; at: number }[] = [];
    const carries: { id: string; at: number }[] = [];
    const parkSoftRefs = rnd() < 0.3;
    const keys = 1 + Math.floor(rnd() * 2);
    for (let k = 0; k < keys; k += 1) {
      const shape = pick(['external', 'fixpoint', 'entity']);
      const target = `attack-pattern--t${k}`;
      if (rnd() < 0.6) {
        // late landings cluster near the park deadlines of the early arrivals
        const lands = rnd() < 0.5 ? at(9000) : DEADLINE - at(1000);
        arrivals.push({ at: lands, intent: producerOf(target) });
        if (rnd() < 0.3) queued.push({ id: target, at: Math.max(0, lands - at(6000)) });
      }
      let endpoint = target;
      if (shape !== 'external') {
        endpoint = `relationship--q${k}`;
        arrivals.push({ at: at(3000), intent: usesOf(target, 'q', { stix: endpoint }) });
      }
      const count = 2 + Math.floor(rnd() * 4);
      // one same-key intent with a soft ref of its own seen queued (B10 head of the lane), landing late or never
      const queuedRefOf = rnd() < 0.35 ? Math.floor(rnd() * count) : -1;
      if (queuedRefOf >= 0) {
        queued.push({ id: `identity--y${k}`, at: at(6000) });
        if (rnd() < 0.6) arrivals.push({ at: at(40_000), intent: producerOf(`identity--y${k}`) });
      }
      for (let i = 0; i < count; i += 1) {
        const user = pick(['c0', 'c1', 'c2']);
        const intent = shape === 'entity'
          ? reportOf(`report--r${k}`, user, [endpoint], rnd() < 0.3 ? [endpoint] : undefined)
          : usesOf(endpoint, user, {
              stix: `relationship--s${k}`,
              description: rnd() < 0.3 ? pick(['d1', 'd2']) : undefined,
              createdBy: i === queuedRefOf ? `identity--y${k}` : (parkSoftRefs && rnd() < 0.4 ? 'identity--x' : undefined),
            });
        arrivals.push({ at: at(6000), intent });
        // lock retries: a run of 1 to 60 consecutive carries (a key held by another platform), from a random time
        if (rnd() < 0.3) {
          const from = at(9000);
          const runs = 1 + Math.floor(rnd() * 60);
          for (let c = 0; c < runs; c += 1) carries.push({ id: intent.id, at: from });
        }
      }
    }
    if (parkSoftRefs && rnd() < 0.5) arrivals.push({ at: at(9000), intent: producerOf('identity--x') });
    // unrelated traffic: producers arriving every 10 to 50 ms, so cycles keep progressing around the shapes above
    if (rnd() < 0.3) {
      const every = 10 + Math.floor(rnd() * 5) * 10;
      const from = at(4000);
      const count = 50 + Math.floor(rnd() * 150);
      for (let n = 0; n < count; n += 1) arrivals.push({ at: from + n * every, intent: producerOf(`attack-pattern--bg${n}`) });
    }
    return { arrivals, queued, carries, parkSoftRefs, untilMs: 300_000 };
  };

  it('holds on 1,000 random shapes: every intent settles, one deadline per park wait, no stateless re-plan, never expired outside a park', () => {
    const failures: string[] = [];
    let outOfOrderSeeds = 0;
    for (let seed = 1; seed <= 1000; seed += 1) {
      const run = simulate(randomRun(seed));
      const problems = liveProblems(run);
      if (problems.length > 0) failures.push(`seed ${seed}: ${problems.join(', ')}`);
      if (run.outOfOrder.length > 0) outOfOrderSeeds += 1;
    }
    expect(failures).toEqual([]);
    // task 0050 lead 43, a ratchet: same-key writes applied out of arrival order on 470 seeds (2026-11-26), never more
    expect(outOfOrderSeeds).toBeLessThanOrEqual(470);
  });

  it('keeps a parked intent expired on its way back through a lane', () => {
    const book = new ParkBook(DEADLINE);
    const intent = relationOf('c0');
    book.route({ order: [], deferred: [], parked: [{ intent, missing: ['attack-pattern--b'] }] }, 0);
    expect(book.expire(book.take(), new Set(), DEADLINE).forceDirect.has(intent.id)).toBe(true);
    // deferred to its lane (a companion), back later: still expired, counted once
    book.route({ order: [], deferred: [{ intent, reason: 'relation' }], parked: [] }, DEADLINE);
    const back = book.expire([intent], new Set(), DEADLINE + 1000);
    expect(back.forceDirect.has(intent.id)).toBe(true);
    expect(back.newlyExpired).toEqual([]);
    // it applies as-is: the wait was counted at the expiry, not again
    expect(book.route({ order: [{ leader: intent, absorbed: [] }], deferred: [], parked: [] }, DEADLINE + 1000).unparked).toEqual([]);
  });

  it('keeps an intent out of its B10 lane wait expired, without counting a park expiry', () => {
    const book = new ParkBook(DEADLINE);
    const intent = relationOf('c0');
    const first = book.expire([intent], new Set([intent.id]), 0);
    expect(first.forceDirect.has(intent.id)).toBe(true);
    expect(first.newlyExpired).toEqual([]);
    expect(book.expire([intent], new Set(), 10).forceDirect.has(intent.id)).toBe(true);
  });

  it('keeps the first deadline across parks; a lane trip or an apply ends the park wait, counted once', () => {
    const book = new ParkBook(DEADLINE);
    const intent = relationOf('c0');
    expect(book.route({ order: [], deferred: [], parked: [{ intent, missing: ['x'] }] }, 0).fresh).toEqual([intent]);
    book.take();
    // to its lane with nothing blocking it: the park wait ends, the deadline stays
    expect(book.route({ order: [], deferred: [{ intent, reason: 'relation' }], parked: [] }, 100)).toEqual({ fresh: [], unparked: [{ intent, waitedMs: 100 }] });
    expect([intent.parkedAt, intent.parkDeadline]).toEqual([undefined, DEADLINE]);
    // not forced while out of its park, even past its deadline
    expect(book.expire([intent], new Set(), DEADLINE + 10).forceDirect.has(intent.id)).toBe(false);
    expect(book.route({ order: [], deferred: [], parked: [{ intent, missing: ['x'] }] }, 2000).fresh).toEqual([]);
    expect(book.nearestDeadline()).toBe(DEADLINE);
    book.take();
    const applied = book.route({ order: [{ leader: intent, absorbed: [] }], deferred: [], parked: [] }, 3000);
    expect(applied.unparked).toEqual([{ intent, waitedMs: 1000 }]);
    expect(book.route({ order: [{ leader: intent, absorbed: [] }], deferred: [], parked: [] }, 3100).unparked).toEqual([]);
    // parked again past its deadline: it expires at the next cycle
    book.route({ order: [], deferred: [], parked: [{ intent, missing: ['x'] }] }, DEADLINE + 100);
    expect(book.expire(book.take(), new Set(), DEADLINE + 110).newlyExpired.map((e) => e.intent)).toEqual([intent]);
  });

  it('restarts the clock on a wait with its own bound: a queued producer, a declared member', () => {
    (['queued_producer', 'member_wait'] as const).forEach((reason) => {
      const book = new ParkBook(DEADLINE);
      const intent = relationOf('c0');
      book.route({ order: [], deferred: [], parked: [{ intent, missing: ['x'] }] }, 0);
      book.take();
      book.route({ order: [], deferred: [{ intent, reason }], parked: [] }, 1000);
      expect([intent.parkDeadline, intent.parkedAt]).toEqual([undefined, undefined]);
      expect(book.route({ order: [], deferred: [], parked: [{ intent, missing: ['x'] }] }, 2000).fresh).toEqual([intent]);
      expect(intent.parkDeadline).toBe(2000 + DEADLINE);
    });
  });

  it('parks a fresh absorbed intent on its leader clock after an apply failure', () => {
    const book = new ParkBook(DEADLINE);
    const leader = relationOf('c0');
    book.route({ order: [], deferred: [], parked: [{ intent: leader, missing: ['x'] }] }, 0);
    book.take();
    const absorbed = relationOf('c0');
    expect(book.parkAfterFailure(leader, [absorbed], 3000)).toEqual({ parked: true, fresh: [absorbed] });
    expect(absorbed.parkDeadline).toBe(DEADLINE);
  });

  it('parks an apply failure on the leader clock, absorbed included, and refuses past it', () => {
    const book = new ParkBook(DEADLINE);
    const leader = relationOf('c0');
    const absorbed = relationOf('c0');
    expect(book.parkAfterFailure(leader, [absorbed], 1000)).toEqual({ parked: true, fresh: [leader, absorbed] });
    expect([leader.parkDeadline, absorbed.parkDeadline]).toEqual([1000 + DEADLINE, 1000 + DEADLINE]);
    book.take();
    expect(book.parkAfterFailure(leader, [absorbed], 2000)).toEqual({ parked: true, fresh: [] });
    expect(leader.parkDeadline).toBe(1000 + DEADLINE);
    book.take();
    expect(book.parkAfterFailure(leader, [absorbed], 1000 + DEADLINE).parked).toBe(false);
    expect(book.size()).toBe(0);
    // out of its B10 lane wait (expired, no clock): it applies as-is, it does not park
    const exhausted = relationOf('c1');
    book.expire([exhausted], new Set([exhausted.id]), 0);
    expect(book.parkAfterFailure(exhausted, [], 0).parked).toBe(false);
  });
});
