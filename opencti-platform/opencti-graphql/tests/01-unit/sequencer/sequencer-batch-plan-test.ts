import { describe, expect, it } from 'vitest';
import { buildBatchPlan, classifyPhase } from '../../../src/database/sequencer/sequencer-batch-plan';
import { buildIntent } from '../../../src/database/sequencer/sequencer-intent';
import type { AuthContext, AuthUser } from '../../../src/types/user';

let arrival = 0;
const intentOf = (args: {
  kind: 'entity' | 'relation';
  type?: string;
  input?: Record<string, any>;
  candidateIds?: string[];
  referencedIds?: string[];
  context?: Record<string, any>;
  opts?: Record<string, any>;
  memberRefIds?: Set<string>;
  user?: string;
  retry?: string | number;
  origin?: Record<string, any>;
  userDraft?: string;
}) => {
  const intent = buildIntent({
    kind: args.kind,
    type: args.type ?? (args.kind === 'entity' ? 'Malware' : 'uses'),
    input: args.input ?? {},
    user: { id: args.user ?? 'u', origin: { applicant_id: 'conn1', call_retry_number: args.retry, ...args.origin }, draft_context: args.userDraft } as unknown as AuthUser,
    context: (args.context ?? {}) as unknown as AuthContext,
    opts: args.opts ?? {},
    candidateIds: args.candidateIds ?? [],
    referencedIds: args.referencedIds ?? [],
    memberRefIds: args.memberRefIds,
    apply: async () => null,
  });
  arrival += 1;
  (intent as any).arrivedAt = arrival; // deterministic ordering for the tests
  return intent;
};

const noResolve = () => null;

describe('sequencer batch plan (plan 0009 D1/D2/D3)', () => {
  it('classifies phases: entity 0, container 2, relation 1, relation on relation 2', () => {
    expect(classifyPhase(intentOf({ kind: 'entity', candidateIds: ['malware--a'] }))).toBe(0);
    expect(classifyPhase(intentOf({ kind: 'entity', type: 'Report', input: { objects: ['x'] }, candidateIds: ['report--r'] }))).toBe(2);
    expect(classifyPhase(intentOf({ kind: 'relation', input: { fromId: 'malware--a', toId: 'identity--b' } }))).toBe(1);
    expect(classifyPhase(intentOf({ kind: 'relation', input: { fromId: 'relationship--x', toId: 'identity--b' } }))).toBe(2);
  });

  it('coalesces identical asserts of the same target; a different input on an UNRESOLVED target defers (no basis to chain on)', () => {
    const a = intentOf({ kind: 'entity', input: { name: 'same' }, candidateIds: ['malware--a'] });
    const b = intentOf({ kind: 'entity', input: { name: 'same' }, candidateIds: ['malware--a'] });
    const c = intentOf({ kind: 'entity', input: { name: 'different' }, candidateIds: ['malware--a'] });
    const plan = buildBatchPlan([a, b, c], noResolve);
    expect(plan.order.length).toBe(1);
    expect(plan.order[0].leader).toBe(a);
    expect(plan.order[0].absorbed).toEqual([b]);
    expect(plan.deferred).toEqual([{ intent: c, reason: 'unresolved_target' }]);
    expect(plan.chainedSteps).toBe(0);
  });

  // GraphQL coerced inputs: null prototype objects, a DateTime as a Date, an Upload as a Promise
  const graphqlInput = (fields: Record<string, any>) => Object.assign(Object.create(null), fields);
  const resolveSector = (id: string) => (id === 'identity--sector' ? 'intSector' : null);

  it('never coalesces inputs differing only by a date, even by 1 ms: the absorbed one would never apply (2026-11-25)', () => {
    const sector = (created: string) => intentOf({ kind: 'entity', type: 'Sector', input: graphqlInput({ name: 'Technology', created: new Date(created) }), candidateIds: ['identity--sector'] });
    const first = sector('2020-06-01T00:00:00.001Z');
    const older = sector('2018-03-01T00:00:00.000Z');
    const sameInstant = sector('2020-06-01T00:00:00.001Z');
    const oneMsLater = sector('2020-06-01T00:00:00.002Z');
    // resolved target: each other date is its own chain step, applied in arrival order; the same instant coalesces
    const resolved = buildBatchPlan([first, older, sameInstant, oneMsLater], resolveSector);
    expect(resolved.order.map((g) => g.leader)).toEqual([first, older, oneMsLater]);
    expect(resolved.order[0].absorbed).toEqual([sameInstant]); // the only kill of a Date read as {}
    expect(resolved.chainedSteps).toBe(2);
    expect(resolved.deferred).toEqual([]);
    // unresolved target: no basis to chain on, the other date waits for a later batch
    const fresh = [sector('2020-06-01T00:00:00.000Z'), sector('2018-03-01T00:00:00.000Z')];
    const unresolved = buildBatchPlan(fresh, noResolve);
    expect(unresolved.order.map((g) => g.leader)).toEqual([fresh[0]]);
    expect(unresolved.order[0].absorbed).toEqual([]);
    expect(unresolved.deferred).toEqual([{ intent: fresh[1], reason: 'unresolved_target' }]);
  });

  it('compares a nested date by its instant in a GraphQL input (null prototype objects, lists)', () => {
    const malware = (at: string) => intentOf({ kind: 'entity', input: graphqlInput({ name: 'm', killChainPhases: [graphqlInput({ phase_name: 'p', at: [new Date(at)] })] }), candidateIds: ['identity--sector'] });
    const a = malware('2020-06-01T00:00:00.000Z');
    const same = malware('2020-06-01T00:00:00.000Z');
    const other = malware('2021-06-01T00:00:00.000Z');
    const plan = buildBatchPlan([a, same, other], resolveSector);
    expect(plan.order.map((g) => g.leader)).toEqual([a, other]);
    expect(plan.order[0].absorbed).toEqual([same]);
  });

  it('never coalesces relations differing only by a date (start_time makes another relationship): the second is deferred', () => {
    const uses = (startTime: string) => intentOf({ kind: 'relation', input: graphqlInput({ fromId: 'malware--a', toId: 'attack-pattern--b', start_time: new Date(startTime) }), candidateIds: ['relationship--stix', 'malware--a', 'attack-pattern--b'] });
    const first = uses('2019-01-01T00:00:00.000Z');
    const same = uses('2019-01-01T00:00:00.000Z');
    const other = uses('2021-01-01T00:00:00.000Z');
    const resolved = buildBatchPlan([first, same, other], (id: string) => `int-${id}`);
    expect(resolved.order.map((g) => g.leader)).toEqual([first]);
    expect(resolved.order[0].absorbed).toEqual([same]);
    expect(resolved.deferred).toEqual([{ intent: other, reason: 'relation' }]);
    // endpoints missing: the group parks (its absorbed follows it), the other start_time parks with them (lead 36)
    const missing = buildBatchPlan([first, same, other], noResolve);
    expect(missing.order).toEqual([]);
    expect(missing.parked).toEqual([first, same, other].map((intent) => ({ intent, missing: ['malware--a', 'attack-pattern--b'] })));
    expect(missing.deferred).toEqual([]);
  });

  describe('same-key relations behind a parked head (task 0040 lead 36)', () => {
    const relationOf = (user: string) => intentOf({ kind: 'relation', input: { fromId: 'malware--a', toId: 'attack-pattern--b' }, candidateIds: ['relationship--stix', 'malware--a', 'attack-pattern--b'], user });
    const fromOnly = (id: string) => (id === 'malware--a' ? 'int-a' : null);

    it('parks a companion with its parked head on the head missing ids; an expired companion goes to its lane', () => {
      const mitre = relationOf('mitre');
      const misp = relationOf('misp');
      const opencti = relationOf('opencti');
      const plan = buildBatchPlan([mitre, misp, opencti], fromOnly, new Set([opencti.id]));
      expect(plan.order).toEqual([]);
      expect(plan.parked).toEqual([{ intent: mitre, missing: ['attack-pattern--b'] }, { intent: misp, missing: ['attack-pattern--b'] }]);
      expect(plan.deferred).toEqual([{ intent: opencti, reason: 'relation' }]);
    });

    // a companion waits the way it would as the head of the next batch: in its lane when nothing blocks it, on its
    // own bound (queued producer, declared member), or parked on its own missing ids
    it('sends a companion to its lane when nothing blocks it (its head applies, or parks on a ref of its own)', () => {
      const applied = buildBatchPlan([relationOf('mitre'), relationOf('misp')], (id) => `int-${id}`);
      expect(applied.deferred.map((d) => d.reason)).toEqual(['relation']);
      // the head parks on its own soft ref (parkSoftRefs), the endpoints exist: the companion can apply on its own
      const softHead = intentOf({ kind: 'relation', input: { fromId: 'malware--a', toId: 'attack-pattern--b', createdBy: 'identity--x' }, candidateIds: ['relationship--stix', 'malware--a', 'attack-pattern--b'], referencedIds: ['identity--x'], user: 'mitre' });
      const soft = buildBatchPlan([softHead, relationOf('misp')], (id) => (id === 'identity--x' ? null : `int-${id}`), new Set(), { parkSoftRefs: true });
      expect(soft.parked).toEqual([{ intent: softHead, missing: ['identity--x'] }]);
      expect(soft.deferred.map((d) => d.reason)).toEqual(['relation']);
    });

    it('parks a blocked companion whatever its head does: expired and applying as-is, condemned, waiting for a member', () => {
      const head = relationOf('mitre');
      const misp = relationOf('misp');
      const expired = buildBatchPlan([head, misp], fromOnly, new Set([head.id]));
      expect(expired.order.map((g) => g.leader)).toEqual([head]);
      expect(expired.parked).toEqual([{ intent: misp, missing: ['attack-pattern--b'] }]);
      const memberHead = (attempts: number) => {
        const intent = intentOf({ kind: 'relation', input: { fromId: 'malware--a', toId: 'attack-pattern--b' }, candidateIds: ['relationship--stix', 'malware--a', 'attack-pattern--b'], user: 'mitre', memberRefIds: new Set(['attack-pattern--b']), context: { deferMissingRefs: true } });
        intent.memberWaitAttempts = attempts;
        return intent;
      };
      // the companion declares no member: the endpoint is external to it
      const companion = () => intentOf({ kind: 'relation', input: { fromId: 'malware--a', toId: 'attack-pattern--b' }, candidateIds: ['relationship--stix', 'malware--a', 'attack-pattern--b'], user: 'misp', context: { deferMissingRefs: true } });
      const finalHead = memberHead(2);
      const finalCompanion = companion();
      const final = buildBatchPlan([finalHead, finalCompanion], fromOnly);
      expect(final.finalMissing.map((f) => f.intent)).toEqual([finalHead]);
      expect(final.parked).toEqual([{ intent: finalCompanion, missing: ['attack-pattern--b'] }]);
      const waitingCompanion = companion();
      const waiting = buildBatchPlan([memberHead(0), waitingCompanion], fromOnly);
      expect(waiting.deferred.map((d) => d.reason)).toEqual(['member_wait']);
      expect(waiting.parked).toEqual([{ intent: waitingCompanion, missing: ['attack-pattern--b'] }]);
    });

    it('defers a companion on its own bound: a queued producer (with what it waits on), a declared member (a pass counted)', () => {
      const queued = buildBatchPlan([relationOf('mitre'), relationOf('misp')], fromOnly, new Set(), { queueHas: (id) => id === 'attack-pattern--b' });
      expect(queued.deferred.map((d) => [d.reason, d.waitingOn])).toEqual([['queued_producer', ['attack-pattern--b']], ['queued_producer', ['attack-pattern--b']]]);
      expect(queued.parked).toEqual([]);
      const member = intentOf({ kind: 'relation', input: { fromId: 'malware--a', toId: 'attack-pattern--b' }, candidateIds: ['relationship--stix', 'malware--a', 'attack-pattern--b'], user: 'misp', memberRefIds: new Set(['attack-pattern--b']) });
      const plan = buildBatchPlan([relationOf('mitre'), member], fromOnly);
      expect(plan.deferred).toEqual([{ intent: member, reason: 'member_wait' }]);
      expect(member.memberWaitAttempts).toBe(1);
      // condemned as a head (dead member, retention): its lane, the next batch rejects or retains it
      const dead = intentOf({ kind: 'relation', input: { fromId: 'malware--a', toId: 'attack-pattern--b' }, candidateIds: ['relationship--stix', 'malware--a', 'attack-pattern--b'], user: 'misp', memberRefIds: new Set(['attack-pattern--b']), context: { deferMissingRefs: true } });
      dead.memberWaitAttempts = 2;
      expect(buildBatchPlan([relationOf('mitre'), dead], fromOnly).deferred).toEqual([{ intent: dead, reason: 'relation' }]);
      // condemned even with another missing endpoint: its lane, not a park
      const both = (user: string, members?: Set<string>) => intentOf({ kind: 'relation', input: { fromId: 'malware--x', toId: 'attack-pattern--b' }, candidateIds: ['relationship--stix', 'malware--x', 'attack-pattern--b'], user, memberRefIds: members, context: { deferMissingRefs: true } });
      const condemned = both('misp', new Set(['attack-pattern--b']));
      condemned.memberWaitAttempts = 2;
      const mixed = buildBatchPlan([both('mitre'), condemned], noResolve);
      expect(mixed.deferred).toEqual([{ intent: condemned, reason: 'relation' }]);
    });

    it('defers a companion on a queued producer before any external missing ref (B10 first, as for a head)', () => {
      const withRef = intentOf({ kind: 'relation', input: { fromId: 'malware--a', toId: 'attack-pattern--b', createdBy: 'identity--y' }, candidateIds: ['relationship--stix', 'malware--a', 'attack-pattern--b'], referencedIds: ['identity--y'], user: 'misp' });
      const plan = buildBatchPlan([relationOf('mitre'), withRef], fromOnly, new Set(), { queueHas: (id) => id === 'identity--y' });
      expect(plan.deferred).toEqual([{ intent: withRef, reason: 'queued_producer', waitingOn: ['identity--y'] }]);
    });

    it('defers the writes of one key to their lane in arrival order, whatever each waits on (lead 38)', () => {
      const waitingOf = () => intentOf({ kind: 'relation', input: { fromId: 'malware--a', toId: 'attack-pattern--b', createdBy: 'identity--y' }, candidateIds: ['relationship--stix', 'malware--a', 'attack-pattern--b'], referencedIds: ['identity--y'], user: 'mitre' });
      const resolve = (id: string) => (id === 'identity--y' ? null : `int-${id}`);
      const options = { queueHas: (id: string) => id === 'identity--y' };
      // the waiting head arrived first: the newer ready write queues behind it (the lane FIFO keeps the order; the
      // wait is the latency cost accepted in round 7), never ahead of it
      const olderWaiting = waitingOf();
      const newerReady = relationOf('misp');
      expect(buildBatchPlan([olderWaiting, newerReady], resolve, new Set(), options).deferred)
        .toEqual([{ intent: olderWaiting, reason: 'queued_producer', waitingOn: ['identity--y'] }, { intent: newerReady, reason: 'relation' }]);
      // the ready write arrived first but comes second in the batch (the loop puts a parked or carried intent after a
      // fresh one): it goes first, not behind the newer waiting head
      const olderReady = relationOf('misp');
      const newerWaiting = waitingOf();
      expect(buildBatchPlan([newerWaiting, olderReady], resolve, new Set(), options).deferred)
        .toEqual([{ intent: olderReady, reason: 'relation' }, { intent: newerWaiting, reason: 'queued_producer', waitingOn: ['identity--y'] }]);
    });

    it('keeps the chain steps of one target in their order in the lane, whatever each waits on (round 7)', () => {
      // a resolved target, two different inputs chained: the first waits on a queued producer, the second on a declared
      // member; released out of order, the older write would land last
      const first = intentOf({ kind: 'entity', input: { name: 'M', description: 'old', createdBy: 'identity--q' }, candidateIds: ['malware--a'], referencedIds: ['identity--q'] });
      const second = intentOf({ kind: 'entity', input: { name: 'M', description: 'new', objectMarking: ['marking-definition--m'] }, candidateIds: ['malware--a'], referencedIds: ['marking-definition--m'], memberRefIds: new Set(['marking-definition--m']) });
      const plan = buildBatchPlan([first, second], (id) => (id === 'malware--a' ? 'int-a' : null), new Set(), { queueHas: (id) => id === 'identity--q' });
      expect(plan.chainedSteps).toBe(1);
      expect(plan.deferred.map((d) => [d.intent, d.reason])).toEqual([[first, 'queued_producer'], [second, 'member_wait']]);
    });

    it('parks a companion behind an in-batch producer that does not apply (fixpoint), on that producer missing ids', () => {
      const producer = () => intentOf({ kind: 'relation', input: { fromId: 'malware--a', toId: 'attack-pattern--b' }, candidateIds: ['relationship--q', 'malware--a', 'attack-pattern--b'], user: 'q' });
      const toQ = (user: string) => intentOf({ kind: 'relation', input: { fromId: 'malware--a', toId: 'relationship--q' }, candidateIds: ['relationship--s', 'malware--a', 'relationship--q'], user });
      const q = producer();
      const head = toQ('c0');
      const other = toQ('c1');
      const plan = buildBatchPlan([q, head, other], fromOnly);
      expect(plan.order).toEqual([]);
      expect(plan.parked).toEqual([q, head, other].map((intent) => ({ intent, missing: ['attack-pattern--b'] })));
      // same-key reports of two connectors behind the parked relation
      const report = (user: string) => intentOf({ kind: 'entity', type: 'Report', input: { objects: ['relationship--q'] }, candidateIds: ['report--r'], referencedIds: ['relationship--q'], user });
      const q2 = producer();
      const first = report('c0');
      const second = report('c1');
      const reports = buildBatchPlan([q2, first, second], fromOnly);
      expect(reports.parked).toEqual([q2, first, second].map((intent) => ({ intent, missing: ['attack-pattern--b'] })));
      expect(reports.deferred).toEqual([]);
    });

    it('routes each companion on its own head (two keys, one head applies, the other parks)', () => {
      const pair = (from: string, to: string, user: string) => intentOf({ kind: 'relation', input: { fromId: from, toId: to }, candidateIds: [`relationship--${from}`, from, to], user });
      const appliedHead = pair('malware--a', 'attack-pattern--ok', 'mitre');
      const appliedCompanion = pair('malware--a', 'attack-pattern--ok', 'misp');
      const parkedHead = pair('malware--a', 'attack-pattern--b', 'mitre');
      const parkedCompanion = pair('malware--a', 'attack-pattern--b', 'misp');
      const plan = buildBatchPlan([appliedHead, parkedHead, appliedCompanion, parkedCompanion], (id) => (id === 'attack-pattern--b' ? null : `int-${id}`));
      expect(plan.order.map((g) => g.leader)).toEqual([appliedHead]);
      expect(plan.deferred).toEqual([{ intent: appliedCompanion, reason: 'relation' }]);
      expect(plan.parked).toEqual([{ intent: parkedHead, missing: ['attack-pattern--b'] }, { intent: parkedCompanion, missing: ['attack-pattern--b'] }]);
    });

    it('never absorbs an expired intent under a fresh leader with the same norm, nor the reverse (C3)', () => {
      const fresh = relationOf('mitre');
      const expired = relationOf('mitre');
      const plan = buildBatchPlan([fresh, expired], fromOnly, new Set([expired.id]));
      expect(plan.parked).toEqual([{ intent: fresh, missing: ['attack-pattern--b'] }]);
      expect(plan.deferred).toEqual([{ intent: expired, reason: 'relation' }]);
      const expiredFirst = relationOf('mitre');
      const freshSecond = relationOf('mitre');
      const reverse = buildBatchPlan([expiredFirst, freshSecond], fromOnly, new Set([expiredFirst.id]));
      expect(reverse.order).toEqual([{ leader: expiredFirst, absorbed: [], dependsOn: [] }]);
      expect(reverse.parked).toEqual([{ intent: freshSecond, missing: ['attack-pattern--b'] }]);
      const bothExpired = [relationOf('mitre'), relationOf('mitre')];
      expect(buildBatchPlan(bothExpired, fromOnly, new Set(bothExpired.map((i) => i.id))).order[0].absorbed).toEqual([bothExpired[1]]);
    });

    it('counts a parked companion as an in-flight producer: a container waiting for it does not burn its member wait', () => {
      const head = relationOf('mitre');
      const companion = intentOf({ kind: 'relation', input: { fromId: 'malware--a', toId: 'attack-pattern--b' }, candidateIds: ['relationship--misp', 'malware--a', 'attack-pattern--b'], user: 'misp' });
      const report = intentOf({ kind: 'entity', type: 'Report', input: { objects: ['relationship--misp'] }, candidateIds: ['report--r'], referencedIds: ['relationship--misp'], memberRefIds: new Set(['relationship--misp']) });
      const plan = buildBatchPlan([head, companion, report], fromOnly);
      expect(plan.parked.map((p) => p.intent)).toEqual([head, companion]);
      expect(plan.deferred).toEqual([{ intent: report, reason: 'queued_producer', waitingOn: ['relationship--misp'] }]);
      expect(report.memberWaitAttempts ?? 0).toBe(0);
    });
  });

  it('never coalesces inputs differing only by an upload: the same promise coalesces, another one does not', () => {
    const shared = Promise.resolve({ filename: 'a.pdf' });
    const malware = (file: Promise<any>) => intentOf({ kind: 'entity', input: graphqlInput({ name: 'same', file }), candidateIds: ['identity--sector'] });
    const first = malware(shared);
    const again = malware(shared);
    const other = malware(Promise.resolve({ filename: 'a.pdf' }));
    const plan = buildBatchPlan([first, again, other], resolveSector);
    expect(plan.order.map((g) => g.leader)).toEqual([first, other]);
    expect(plan.order[0].absorbed).toEqual([again]);
  });

  it('never coalesces equal inputs of two users: each upsert records its user under its own confidence', () => {
    const sector = (user: string) => intentOf({ kind: 'entity', type: 'Sector', input: graphqlInput({ name: 'Technology' }), candidateIds: ['identity--sector'], user });
    const mitre = sector('mitre');
    const mitreAgain = sector('mitre');
    const misp = sector('misp');
    const resolved = buildBatchPlan([mitre, mitreAgain, misp], resolveSector);
    expect(resolved.order.map((g) => g.leader)).toEqual([mitre, misp]);
    expect(resolved.order[0].absorbed).toEqual([mitreAgain]);
    const unresolved = buildBatchPlan([sector('mitre'), sector('misp')], noResolve);
    expect(unresolved.deferred.map((d) => d.reason)).toEqual(['unresolved_target']);
  });

  it('never coalesces inputs differing only by an upload in a list', () => {
    const malware = (file: Promise<any>) => intentOf({ kind: 'entity', input: graphqlInput({ name: 'same', files: [file] }), candidateIds: ['identity--sector'] });
    const first = malware(Promise.resolve({ filename: 'a.pdf' }));
    const other = malware(Promise.resolve({ filename: 'a.pdf' }));
    const plan = buildBatchPlan([first, other], resolveSector);
    expect(plan.order.map((g) => g.leader)).toEqual([first, other]);
  });

  describe('opts and apply context in the norm (task 0040 review 2026-11-25)', () => {
    type Variant = { opts?: Record<string, any>; context?: Record<string, any>; retry?: string | number; origin?: Record<string, any>; userDraft?: string };
    const sector = (variant: Variant) => intentOf({ kind: 'entity', type: 'Sector', input: graphqlInput({ name: 'Technology' }), candidateIds: ['identity--sector'], ...variant });
    // what the second intent becomes: a chain step on the resolved target, or the deferral a refused chain gives
    const pathOf = (a: Variant, b: Variant) => {
      const plain = sector(a);
      const differing = sector(b);
      const plan = buildBatchPlan([plain, differing], resolveSector);
      if (plan.order.some((g) => g.absorbed.includes(differing))) return 'absorbed';
      if (plan.order.some((g) => g.leader === differing)) return 'step';
      return plan.deferred.find((d) => d.intent === differing)?.reason;
    };

    it.each([
      ['opts value', { opts: { complete: true } }, { opts: { complete: false } }, 'step'],
      ['nested opts value', { opts: { nested: { a: 1 } } }, { opts: { nested: { a: 2 } } }, 'step'],
      ['replay event id', { context: { eventId: '1-0' } }, { context: { eventId: '2-0' } }, 'self_not_foldable'],
      ['full sync', { context: { synchronizedUpsert: true } }, { context: { synchronizedUpsert: false } }, 'head_not_foldable'],
      ['previous standard id', { context: { previousStandard: 'identity--old' } }, { context: { previousStandard: 'identity--older' } }, 'step'],
      ['draft', { context: { draft_context: 'draft1' } }, { context: { draft_context: 'draft2' } }, 'step'],
      ['create-only form import', { context: { form_submission: true } }, { context: { form_submission: false } }, 'step'],
      // a chunk-path intent (retained on a missing reference) under an HTTP leader (rejected)
      ['missing reference retention', { context: { deferMissingRefs: true } }, { context: { deferMissingRefs: false } }, 'step'],
      // an unresolved optional ref rejects while the worker retry number is at most 2 (strip-and-reconcile off)
      ['reject-twice retry', { retry: '0' }, { retry: '5' }, 'step'],
      ['reject-twice retry at its bound', { retry: '2' }, { retry: '3' }, 'step'],
      // the resubmit fallback sets the number 0: `retryNumber &&` does not reject; pycti sends the string '0'
      ['reject-twice retry 0 as a number', { retry: 0 }, { retry: '0' }, 'step'],
      ['user draft', { userDraft: 'draft1' }, { userDraft: 'draft2' }, 'step'],
      ['connector (applicant)', { origin: { applicant_id: 'conn1' } }, { origin: { applicant_id: 'conn2' } }, 'step'],
      ['playbook', { origin: { playbook_id: 'pb1' } }, { origin: { playbook_id: 'pb2' } }, 'step'],
    ] as [string, Variant, Variant, string][])('never absorbs an intent differing by its %s', (_, a, b, path) => {
      expect(pathOf(a, b)).toBe(path);
    });

    it.each([
      ['same opts and context', { opts: { complete: true, nested: { a: 1 } }, context: { deferMissingRefs: true, form_submission: true } }, { opts: { nested: { a: 1 }, complete: true }, context: { form_submission: true, deferMissingRefs: true } }],
      ['false and absent flags', { context: { deferMissingRefs: false, synchronizedUpsert: false, form_submission: false } }, {}],
      // the user by its id: another attempt of the same connector is the same apply
      ['retry numbers on the same side of 2', { retry: '0' }, { retry: '1' }],
      ['retry numbers up to 2', { retry: '1' }, { retry: '2' }],
      // the apply reads form_submission === true only
      ['a form flag that is not true', { context: { form_submission: 'yes' } }, {}],
    ] as [string, Variant, Variant][])('still coalesces with %s', (_, a, b) => {
      expect(pathOf(a, b)).toBe('absorbed');
    });
  });

  it('still coalesces equal GraphQL inputs (null prototype objects, nested too) by their content', () => {
    const of = () => intentOf({ kind: 'entity', input: graphqlInput({ name: 'same', killChainPhases: [graphqlInput({ phase_name: 'p' })] }), candidateIds: ['malware--a'] });
    const a = of();
    const b = of();
    const plan = buildBatchPlan([a, b], noResolve);
    expect(plan.order.map((g) => g.leader)).toEqual([a]);
    expect(plan.order[0].absorbed).toEqual([b]);
  });

  it('keys an unknown entity on its standard id: twins asserted under two STIX ids share one chain, the second defers (2026-09-21)', () => {
    // the same malware from two ATT&CK collections: same standard id first, different STIX ids and inputs
    const enterprise = intentOf({ kind: 'entity', input: { name: 'Industroyer', stix_id: 'malware--1d8d' }, candidateIds: ['malware--4f2e', 'malware--1d8d'] });
    const ics = intentOf({ kind: 'entity', input: { name: 'Industroyer', stix_id: 'malware--e401' }, candidateIds: ['malware--4f2e', 'malware--e401'] });
    const other = intentOf({ kind: 'entity', input: { name: 'Other' }, candidateIds: ['malware--zzzz', 'malware--0000'] });
    const plan = buildBatchPlan([enterprise, ics, other], noResolve);
    expect(plan.order.map((g) => g.leader)).toEqual([enterprise, other]);
    expect(plan.deferred).toEqual([{ intent: ics, reason: 'unresolved_target' }]);
  });

  it('chains a different input on a RESOLVED entity target behind the previous write (P2 merge-fold)', () => {
    const a = intentOf({ kind: 'entity', input: { name: 'ACME', aliases: ['A1'] }, candidateIds: ['identity--org'] });
    const b = intentOf({ kind: 'entity', input: { name: 'ACME', aliases: ['A2'] }, candidateIds: ['identity--org'] });
    const c = intentOf({ kind: 'entity', input: { name: 'ACME', aliases: ['A1'] }, candidateIds: ['identity--org'] });
    const resolve = (id: string) => (id === 'identity--org' ? 'intOrg' : null);
    const plan = buildBatchPlan([a, b, c], resolve);
    // a then b as ordered chain steps; c absorbs into a's step (identical norm)
    expect(plan.order.map((g) => g.leader)).toEqual([a, b]);
    expect(plan.order[0].absorbed).toEqual([c]);
    expect(plan.deferred).toEqual([]);
    expect(plan.chainedSteps).toBe(1);
  });

  it('a consumer of a chained target orders after the chain HEAD (existence), not the tail', () => {
    const step1 = intentOf({ kind: 'entity', type: 'Organization', input: { name: 'ACME', aliases: ['A1'] }, candidateIds: ['identity--org'] });
    const step2 = intentOf({ kind: 'entity', type: 'Organization', input: { name: 'ACME', aliases: ['A2'] }, candidateIds: ['identity--org'] });
    const consumer = intentOf({ kind: 'entity', input: { name: 'M', createdBy: 'identity--org' }, candidateIds: ['malware--m'], referencedIds: ['identity--org'] });
    const resolve = (id: string) => (id === 'identity--org' ? 'intOrg' : null);
    const plan = buildBatchPlan([consumer, step1, step2], resolve);
    const orderedLeaders = plan.order.map((g) => g.leader);
    expect(orderedLeaders.indexOf(step1)).toBeLessThan(orderedLeaders.indexOf(step2));
    expect(orderedLeaders.indexOf(step1)).toBeLessThan(orderedLeaders.indexOf(consumer));
  });

  it('does not chain a RELATION with a different input on the same (from, to, type): residual deferral (T5 out of scope)', () => {
    const r1 = intentOf({ kind: 'relation', input: { fromId: 'malware--a', toId: 'identity--b', confidence: 10 }, candidateIds: [] });
    const r2 = intentOf({ kind: 'relation', input: { fromId: 'malware--a', toId: 'identity--b', confidence: 80 }, candidateIds: [] });
    const resolve = (id: string) => (id === 'malware--a' ? 'intA' : id === 'identity--b' ? 'intB' : null);
    const plan = buildBatchPlan([r1, r2], resolve);
    expect(plan.order.map((g) => g.leader)).toEqual([r1]);
    expect(plan.deferred).toEqual([{ intent: r2, reason: 'relation' }]);
    expect(plan.chainedSteps).toBe(0);
  });

  it('does not chain onto a forceDirect (expired) head, and a forceDirect companion defers instead of joining a chain', () => {
    const expired = intentOf({ kind: 'entity', input: { name: 'ACME', aliases: ['A1'] }, candidateIds: ['identity--org'] });
    const fresh = intentOf({ kind: 'entity', input: { name: 'ACME', aliases: ['A2'] }, candidateIds: ['identity--org'] });
    const resolve = (id: string) => (id === 'identity--org' ? 'intOrg' : null);
    // expired head: the fresh companion must defer, not chain
    const planA = buildBatchPlan([expired, fresh], resolve, new Set([expired.id]));
    expect(planA.order.map((g) => g.leader)).toEqual([expired]);
    expect(planA.deferred).toEqual([{ intent: fresh, reason: 'head_not_foldable' }]);
    // expired companion arriving on a live chain head: it defers, the head applies
    const head = intentOf({ kind: 'entity', input: { name: 'ACME', aliases: ['A1'] }, candidateIds: ['identity--org'] });
    const expired2 = intentOf({ kind: 'entity', input: { name: 'ACME', aliases: ['A3'] }, candidateIds: ['identity--org'] });
    const planB = buildBatchPlan([head, expired2], resolve, new Set([expired2.id]));
    expect(planB.order.map((g) => g.leader)).toEqual([head]);
    expect(planB.deferred).toEqual([{ intent: expired2, reason: 'force_direct' }]);
  });

  it('does not chain enforced-reference commits or replay contexts: residual deferral', () => {
    const resolve = (id: string) => (id === 'identity--org' ? 'intOrg' : null);
    const head = intentOf({ kind: 'entity', input: { name: 'ACME', aliases: ['A1'] }, candidateIds: ['identity--org'] });
    const commit = intentOf({ kind: 'entity', input: { name: 'ACME', aliases: ['A2'] }, candidateIds: ['identity--org'], opts: { references: ['ref1'] } });
    const replay = intentOf({ kind: 'entity', input: { name: 'ACME', aliases: ['A3'] }, candidateIds: ['identity--org'], context: { eventId: '123-0' } });
    const plan = buildBatchPlan([head, commit, replay], resolve);
    expect(plan.order.map((g) => g.leader)).toEqual([head]);
    expect(plan.deferred).toEqual([{ intent: commit, reason: 'self_not_foldable' }, { intent: replay, reason: 'self_not_foldable' }]);
    expect(plan.chainedSteps).toBe(0);
  });

  it('parks a whole chain when its head parks (fixpoint through the chain edge)', () => {
    const resolve = (id: string) => (id === 'identity--org' ? 'intOrg' : null);
    const head = intentOf({ kind: 'entity', input: { name: 'ACME', createdBy: 'identity--missing', aliases: ['A1'] }, candidateIds: ['identity--org'], referencedIds: ['identity--missing'] });
    const step2 = intentOf({ kind: 'entity', input: { name: 'ACME', aliases: ['A2'] }, candidateIds: ['identity--org'] });
    const plan = buildBatchPlan([head, step2], resolve, new Set(), { parkSoftRefs: true });
    expect(plan.order).toEqual([]);
    expect(plan.parked.map((p) => p.intent)).toContain(head);
    expect(plan.parked.map((p) => p.intent)).toContain(step2);
  });

  it('coalesces relations by (from, to, type) with identical input', () => {
    const r1 = intentOf({ kind: 'relation', input: { fromId: 'malware--a', toId: 'identity--b' }, candidateIds: [] });
    const r2 = intentOf({ kind: 'relation', input: { fromId: 'malware--a', toId: 'identity--b' }, candidateIds: [] });
    const resolve = (id: string) => (id === 'malware--a' ? 'intA' : id === 'identity--b' ? 'intB' : null);
    const plan = buildBatchPlan([r1, r2], resolve);
    expect(plan.order.length).toBe(1);
    expect(plan.order[0].absorbed).toEqual([r2]);
  });

  it('orders a producer before its same-phase consumer (D2, b2 -> b1)', () => {
    const org = intentOf({ kind: 'entity', type: 'Organization', input: { name: 'ACME' }, candidateIds: ['identity--org'] });
    const malware = intentOf({ kind: 'entity', input: { name: 'M', createdBy: 'identity--org' }, candidateIds: ['malware--m'], referencedIds: ['identity--org'] });
    // consumer arrives FIRST: the edge must still order it after its producer
    const plan = buildBatchPlan([malware, org], noResolve);
    expect(plan.order.map((g) => g.leader)).toEqual([org, malware]);
    expect(plan.parked).toEqual([]);
  });

  it('orders a relation after its in-batch endpoint producer (m5 -> m6)', () => {
    const rel = intentOf({ kind: 'relation', input: { fromId: 'malware--m', toId: 'software--openssl' }, candidateIds: [] });
    const endpoint = intentOf({ kind: 'entity', type: 'Software', input: { name: 'openssl' }, candidateIds: ['software--openssl'] });
    const resolve = (id: string) => (id === 'malware--m' ? 'intM' : null);
    const plan = buildBatchPlan([rel, endpoint], resolve);
    expect(plan.order.map((g) => g.leader)).toEqual([endpoint, rel]);
  });

  it('parks an intent whose reference nobody resolves or produces (D2)', () => {
    const rel = intentOf({ kind: 'relation', input: { fromId: 'malware--m', toId: 'software--unknown' }, candidateIds: [] });
    const resolve = (id: string) => (id === 'malware--m' ? 'intM' : null);
    const plan = buildBatchPlan([rel], resolve);
    expect(plan.order).toEqual([]);
    expect(plan.parked.length).toBe(1);
    expect(plan.parked[0].missing).toEqual(['software--unknown']);
  });

  it('parks an entity on an unresolved soft reference with no producer (D2 v3, opt-in)', () => {
    const entity = intentOf({ kind: 'entity', input: { name: 'M', createdBy: 'identity--missing' }, candidateIds: ['malware--m'], referencedIds: ['identity--missing'] });
    const plan = buildBatchPlan([entity], noResolve, new Set(), { parkSoftRefs: true });
    expect(plan.order).toEqual([]);
    expect(plan.parked.length).toBe(1);
    expect(plan.parked[0].missing).toEqual(['identity--missing']);
  });

  it('by default (D2 v2) an unresolved soft reference with no producer applies as today, never parks', () => {
    const entity = intentOf({ kind: 'entity', input: { name: 'M', createdBy: 'identity--missing' }, candidateIds: ['malware--m'], referencedIds: ['identity--missing'] });
    const plan = buildBatchPlan([entity], noResolve);
    expect(plan.parked).toEqual([]);
    expect(plan.order.map((g) => g.leader)).toEqual([entity]);
  });

  it('never parks on auto-created reference families (labels, external refs, kill chains, vocabs), even with v3 on', () => {
    const entity = intentOf({
      kind: 'entity',
      input: { name: 'M', objectLabel: ['label--x'], externalReferences: ['external-reference--y'], killChainPhases: ['kill-chain-phase--z'] },
      candidateIds: ['malware--m'],
      referencedIds: ['label--x', 'external-reference--y', 'kill-chain-phase--z', 'vocabulary--v'],
    });
    const plan = buildBatchPlan([entity], noResolve, new Set(), { parkSoftRefs: true });
    expect(plan.parked).toEqual([]);
    expect(plan.order.map((g) => g.leader)).toEqual([entity]); // applies as today (auto-create)
  });

  it('a resolved soft reference does not park (D2 v3)', () => {
    const entity = intentOf({ kind: 'entity', input: { name: 'M', createdBy: 'identity--known' }, candidateIds: ['malware--m'], referencedIds: ['identity--known'] });
    const resolve = (id: string) => (id === 'identity--known' ? 'intK' : null);
    const plan = buildBatchPlan([entity], resolve);
    expect(plan.parked).toEqual([]);
    expect(plan.order.map((g) => g.leader)).toEqual([entity]);
  });

  it('force-directs an expired intent: applied as-is, never parked (D2 deadline)', () => {
    const rel = intentOf({ kind: 'relation', input: { fromId: 'malware--m', toId: 'software--unknown' }, candidateIds: [] });
    const plan = buildBatchPlan([rel], noResolve, new Set([rel.id]));
    expect(plan.parked).toEqual([]);
    expect(plan.order.map((g) => g.leader)).toEqual([rel]);
  });

  it('cascades parking to consumers of a parked producer (rel-of-rel on a parked relation)', () => {
    const producer = intentOf({ kind: 'relation', input: { fromId: 'malware--p', toId: 'software--unknown' }, candidateIds: ['relationship--r1'] });
    const consumer = intentOf({ kind: 'relation', input: { fromId: 'relationship--r1', toId: 'identity--b' }, candidateIds: [] });
    const resolve = (id: string) => (id === 'malware--p' ? 'intP' : id === 'identity--b' ? 'intB' : null);
    const plan = buildBatchPlan([producer, consumer], resolve);
    expect(plan.order).toEqual([]);
    expect(plan.parked.map((p) => p.intent)).toContain(producer);
    expect(plan.parked.map((p) => p.intent)).toContain(consumer);
  });

  it('gives an intent with NO candidate ids a key of its own: no collision, no deferral (2026-08-31 boundary fix guard)', () => {
    const l1 = intentOf({ kind: 'entity', type: 'Label', input: { value: 'apt' }, candidateIds: [] });
    const l2 = intentOf({ kind: 'entity', type: 'Label', input: { value: 'ransomware' }, candidateIds: [] });
    const m = intentOf({ kind: 'entity', type: 'Marking-Definition', input: { definition: 'TLP:RED' }, candidateIds: [] });
    const plan = buildBatchPlan([l1, l2, m], noResolve);
    expect(plan.deferred).toEqual([]);
    expect(plan.order.map((g) => g.leader)).toEqual([l1, l2, m]);
    expect(plan.chainedSteps).toBe(0);
  });

  it('defers with certainty when a missing in-bundle ref has its producer in the queue (s9.8.2)', () => {
    const rel = intentOf({ kind: 'relation', input: { fromId: 'malware--m', toId: 'software--s' }, candidateIds: [], memberRefIds: new Set(['software--s']) });
    const resolve = (id: string) => (id === 'malware--m' ? 'intM' : null);
    const plan = buildBatchPlan([rel], resolve, new Set(), { queueHas: (id) => id === 'software--s' });
    expect(plan.order).toEqual([]);
    expect(plan.parked).toEqual([]);
    expect(plan.deferred).toEqual([{ intent: rel, reason: 'queued_producer', waitingOn: ['software--s'] }]);
    expect(plan.finalMissing).toEqual([]);
  });

  it('waits a bounded number of passes for a declared member not yet seen, then rejects final (member dead) when the caller has retention', () => {
    const rel = intentOf({ kind: 'relation', input: { fromId: 'malware--m', toId: 'software--s' }, candidateIds: [], memberRefIds: new Set(['software--s']), context: { deferMissingRefs: true } });
    const resolve = (id: string) => (id === 'malware--m' ? 'intM' : null);
    const opts = { queueHas: () => false, memberWaitLimit: 2 };
    const p1 = buildBatchPlan([rel], resolve, new Set(), opts);
    expect(p1.deferred).toEqual([{ intent: rel, reason: 'member_wait' }]);
    const p2 = buildBatchPlan([rel], resolve, new Set(), opts);
    expect(p2.deferred).toEqual([{ intent: rel, reason: 'member_wait' }]);
    const p3 = buildBatchPlan([rel], resolve, new Set(), opts);
    expect(p3.deferred).toEqual([]);
    expect(p3.finalMissing).toEqual([{ intent: rel, missing: ['software--s'] }]);
  });

  it('a missing ref NOT declared in the bundle keeps today path: hard parks, soft applies (external)', () => {
    const rel = intentOf({ kind: 'relation', input: { fromId: 'malware--m', toId: 'software--unknown' }, candidateIds: [], memberRefIds: new Set(['other--x']) });
    const resolve = (id: string) => (id === 'malware--m' ? 'intM' : null);
    const planHard = buildBatchPlan([rel], resolve, new Set(), { queueHas: () => false });
    expect(planHard.parked.length).toBe(1);
    expect(planHard.finalMissing).toEqual([]);
    const entity = intentOf({ kind: 'entity', input: { name: 'M', createdBy: 'identity--ext' }, candidateIds: ['malware--m'], referencedIds: ['identity--ext'], memberRefIds: new Set(['other--x']) });
    const planSoft = buildBatchPlan([entity], noResolve, new Set(), { queueHas: () => false });
    expect(planSoft.order.map((g) => g.leader)).toEqual([entity]); // applies as today
  });

  it('soft member refs use the certainty rules without needing parkSoftRefs', () => {
    const entity = intentOf({ kind: 'entity', input: { name: 'M', createdBy: 'identity--i' }, candidateIds: ['malware--m'], referencedIds: ['identity--i'], memberRefIds: new Set(['identity--i']) });
    const plan = buildBatchPlan([entity], noResolve, new Set(), { queueHas: (id) => id === 'identity--i' });
    expect(plan.deferred).toEqual([{ intent: entity, reason: 'queued_producer', waitingOn: ['identity--i'] }]);
  });

  it('defers with certainty when a missing EXTERNAL ref has its producer in the queue (s9.10.2)', () => {
    const rel = intentOf({ kind: 'relation', input: { fromId: 'malware--m', toId: 'software--s' }, candidateIds: [] });
    const resolve = (id: string) => (id === 'malware--m' ? 'intM' : null);
    const plan = buildBatchPlan([rel], resolve, new Set(), { queueHas: (id) => id === 'software--s' });
    expect(plan.deferred).toEqual([{ intent: rel, reason: 'queued_producer', waitingOn: ['software--s'] }]);
    expect(plan.parked).toEqual([]); // before s9.10 this hard external ref parked
  });

  it('strips dead SOFT member refs and applies the container without them (s9.10.2)', () => {
    const note = intentOf({
      kind: 'entity',
      type: 'Note',
      input: { name: 'N', objects: ['vulnerability--v', 'report--r'], createdBy: 'identity--dead' },
      candidateIds: ['note--n'],
      referencedIds: ['vulnerability--v', 'report--r', 'identity--dead'],
      memberRefIds: new Set(['vulnerability--v', 'identity--dead']),
    });
    const resolve = (id: string) => (id === 'report--r' ? 'intR' : null);
    const opts = { queueHas: () => false, memberWaitLimit: 2 };
    expect(buildBatchPlan([note], resolve, new Set(), opts).deferred.map((d) => d.reason)).toEqual(['member_wait']);
    expect(buildBatchPlan([note], resolve, new Set(), opts).deferred.map((d) => d.reason)).toEqual(['member_wait']);
    const p3 = buildBatchPlan([note], resolve, new Set(), opts);
    expect(p3.finalMissing).toEqual([]); // soft dead refs no longer condemn the container
    expect(p3.strippedDead).toEqual([{ intent: note, stripped: ['vulnerability--v', 'identity--dead'] }]);
    expect(p3.order.map((g) => g.leader)).toEqual([note]);
    expect(note.input.objects).toEqual(['report--r']); // dead array entry removed
    expect(note.input.createdBy).toBeNull(); // dead scalar ref nulled
    expect(note.referencedIds).toEqual(['report--r']);
  });

  it('a dead HARD member ref (relation endpoint) rejects final when the caller has retention, no strip (s9.10.2)', () => {
    const rel = intentOf({ kind: 'relation', input: { fromId: 'malware--m', toId: 'software--s' }, candidateIds: [], memberRefIds: new Set(['software--s']), context: { deferMissingRefs: true } });
    rel.memberWaitAttempts = 2; // bounded wait already exhausted
    const resolve = (id: string) => (id === 'malware--m' ? 'intM' : null);
    const plan = buildBatchPlan([rel], resolve, new Set(), { queueHas: () => false, memberWaitLimit: 2 });
    expect(plan.strippedDead).toEqual([]);
    expect(plan.finalMissing).toEqual([{ intent: rel, missing: ['software--s'] }]);
  });

  it('a dead HARD member ref PARKS instead of final when the caller has no retention (B16, 2026-09-24)', () => {
    const rel = intentOf({ kind: 'relation', input: { fromId: 'malware--m', toId: 'software--s' }, candidateIds: [], memberRefIds: new Set(['software--s']) });
    rel.memberWaitAttempts = 2;
    const resolve = (id: string) => (id === 'malware--m' ? 'intM' : null);
    const plan = buildBatchPlan([rel], resolve, new Set(), { queueHas: () => false, memberWaitLimit: 2 });
    expect(plan.finalMissing).toEqual([]);
    expect(plan.order).toEqual([]);
    expect(plan.parked).toEqual([{ intent: rel, missing: ['software--s'] }]);
  });

  it('exposes producer positions as dependsOn in the order (s9.9 failure-aware execution)', () => {
    const org = intentOf({ kind: 'entity', type: 'Organization', input: { name: 'ACME' }, candidateIds: ['identity--org'] });
    const malware = intentOf({ kind: 'entity', input: { name: 'M', createdBy: 'identity--org' }, candidateIds: ['malware--m'], referencedIds: ['identity--org'] });
    const rel = intentOf({ kind: 'relation', input: { fromId: 'malware--m', toId: 'identity--org' }, candidateIds: [] });
    const plan = buildBatchPlan([rel, malware, org], noResolve);
    const pos = (i: any) => plan.order.findIndex((g) => g.leader === i);
    expect(plan.order[pos(org)].dependsOn).toEqual([]);
    expect(plan.order[pos(malware)].dependsOn).toEqual([pos(org)]);
    expect([...(plan.order[pos(rel)].dependsOn ?? [])].sort()).toEqual([pos(org), pos(malware)].sort());
  });

  it('breaks cycles by arrival order', () => {
    const report = intentOf({ kind: 'entity', type: 'Report', input: { objects: ['note--n'] }, candidateIds: ['report--r'], referencedIds: ['note--n'] });
    const note = intentOf({ kind: 'entity', type: 'Note', input: { objects: ['report--r'] }, candidateIds: ['note--n'], referencedIds: ['report--r'] });
    const plan = buildBatchPlan([report, note], noResolve);
    expect(plan.order.length).toBe(2);
    expect(plan.order[0].leader).toBe(report); // first arrived wins the cycle break
    expect(plan.parked).toEqual([]);
  });
});

// Fix 2026-09-21: intake-shaped relations (candidateIds carry stix id AND fromId/toId) must
// still plan their endpoints. Every test above passes candidateIds: [] for relations, which
// hid the defect: the own-id filter on candidateIds dropped every endpoint dependency.
describe('sequencer batch plan: relation endpoints with intake-shaped candidate ids', () => {
  const relOf = (from: string, to: string, stixId: string, extra: Record<string, any> = {}) => intentOf({
    kind: 'relation',
    input: { fromId: from, toId: to, stix_id: stixId },
    candidateIds: [stixId, from, to],
    referencedIds: [from, to],
    ...extra,
  });
  const orgResolved = (id: string) => (id === 'identity--org' ? 'int-org' : null);

  it('orders a relation after its in-batch endpoint producer, with a dependsOn edge', () => {
    const malware = intentOf({ kind: 'entity', input: { name: 'M' }, candidateIds: ['malware--m', 'malware--m-stix'] });
    const rel = relOf('malware--m-stix', 'identity--org', 'relationship--1');
    const plan = buildBatchPlan([rel, malware], orgResolved);
    const pos = (i: any) => plan.order.findIndex((g) => g.leader === i);
    expect(pos(malware)).toBeLessThan(pos(rel));
    expect(plan.order[pos(rel)].dependsOn).toEqual([pos(malware)]);
  });

  it('never admits a relation whose endpoint is absent: queued producer defers, declared member waits, external parks', () => {
    const queued = relOf('malware--q', 'identity--org', 'relationship--q');
    const member = relOf('malware--w', 'identity--org', 'relationship--w', { memberRefIds: new Set(['malware--w']) });
    const external = relOf('malware--x', 'identity--org', 'relationship--x');
    const plan = buildBatchPlan([queued, member, external], orgResolved, new Set(), { queueHas: (id) => id === 'malware--q', memberWaitLimit: 2 });
    expect(plan.order).toEqual([]);
    expect(plan.deferred.map((d) => [d.intent, d.reason])).toEqual([[queued, 'queued_producer'], [member, 'member_wait']]);
    expect(plan.parked.map((p) => p.intent)).toEqual([external]);
  });

  it('a relation is never the producer of its endpoints for another relation', () => {
    const r1 = relOf('malware--m', 'identity--org', 'relationship--1');
    const r2 = relOf('malware--m', 'identity--other', 'relationship--2');
    const plan = buildBatchPlan([r1, r2], (id) => (id.startsWith('identity--') ? `int-${id}` : null), new Set(), { queueHas: () => false });
    expect(plan.order).toEqual([]);
    expect(plan.parked.map((p) => p.intent)).toEqual([r1, r2]);
  });
});

describe('auto-created references with a producer in flight (single wave, 2026-09-24)', () => {
  const resolveNone = () => null;

  it('waits for a queued label producer instead of assuming an auto-create at apply', () => {
    const coa = intentOf({ kind: 'entity', type: 'Course-Of-Action', input: { name: 'M1', objectLabel: ['label--nist'] }, candidateIds: ['course-of-action--m1'], referencedIds: ['label--nist'] });
    const plan = buildBatchPlan([coa], resolveNone, new Set(), { queueHas: (id) => id === 'label--nist' });
    expect(plan.order).toEqual([]);
    expect(plan.deferred).toEqual([{ intent: coa, reason: 'queued_producer', waitingOn: ['label--nist'] }]);
  });

  it('waits a bounded number of passes for a label declared as an in-chunk member', () => {
    const coa = intentOf({ kind: 'entity', type: 'Course-Of-Action', input: { name: 'M1', objectLabel: ['label--nist'] }, candidateIds: ['course-of-action--m1'], referencedIds: ['label--nist'], memberRefIds: new Set(['label--nist']) });
    const plan = buildBatchPlan([coa], resolveNone, new Set(), { queueHas: () => false, memberWaitLimit: 2 });
    expect(plan.order).toEqual([]);
    expect(plan.deferred).toEqual([{ intent: coa, reason: 'member_wait' }]);
  });

  it('keeps the auto-create assumption for a label nobody has in flight', () => {
    const coa = intentOf({ kind: 'entity', type: 'Course-Of-Action', input: { name: 'M1', objectLabel: ['label--nist'] }, candidateIds: ['course-of-action--m1'], referencedIds: ['label--nist'] });
    const plan = buildBatchPlan([coa], resolveNone, new Set(), { queueHas: () => false });
    expect(plan.order.length).toBe(1);
    expect(plan.deferred).toEqual([]);
    expect(plan.parked).toEqual([]);
  });

  it('orders a consumer after its co-batched label producer', () => {
    const label = intentOf({ kind: 'entity', type: 'Label', input: { value: 'nist' }, candidateIds: ['label--nist'] });
    const coa = intentOf({ kind: 'entity', type: 'Course-Of-Action', input: { name: 'M1', objectLabel: ['label--nist'] }, candidateIds: ['course-of-action--m1'], referencedIds: ['label--nist'] });
    const plan = buildBatchPlan([coa, label], resolveNone, new Set(), { queueHas: () => false });
    expect(plan.order.map((g) => g.leader)).toEqual([label, coa]);
    expect(plan.deferred).toEqual([]);
  });
});

// task 0040 (multi-writer diag 2026-11-12): a relation deferred because another one in the batch
// targets the same relation (same from, to and type, another input) lands in a later batch. A
// container declaring it as a member waits for it as for a queued producer: its bounded member
// wait is not spent, so a busy relation target no longer gets the container's ref stripped dead.
describe('sequencer batch plan: member deferred behind the same relation target', () => {
  it('should wait for a member deferred in this batch without spending a member wait attempt', () => {
    const leader = intentOf({ kind: 'relation', type: 'targets', input: { fromId: 'intrusion-set--conti', toId: 'identity--sector', stix_id: 'relationship--a' }, candidateIds: ['relationship--a', 'intrusion-set--conti', 'identity--sector'], referencedIds: ['intrusion-set--conti', 'identity--sector'] });
    const twin = intentOf({ kind: 'relation', type: 'targets', input: { fromId: 'intrusion-set--conti', toId: 'identity--sector', stix_id: 'relationship--b' }, candidateIds: ['relationship--b', 'intrusion-set--conti', 'identity--sector'], referencedIds: ['intrusion-set--conti', 'identity--sector'] });
    const report = intentOf({ kind: 'entity', type: 'Report', input: { name: 'R', objects: ['relationship--b'] }, candidateIds: ['report--r'], referencedIds: ['relationship--b'], memberRefIds: new Set(['relationship--b']) });
    const resolve = (id: string) => (id === 'intrusion-set--conti' || id === 'identity--sector' ? `int-${id}` : null);
    const plan = buildBatchPlan([leader, twin, report], resolve, new Set(), { queueHas: () => false, memberWaitLimit: 2 });
    expect(plan.deferred).toContainEqual({ intent: twin, reason: 'relation' });
    expect(plan.deferred).toContainEqual({ intent: report, reason: 'queued_producer', waitingOn: ['relationship--b'] });
    expect(report.memberWaitAttempts ?? 0).toBe(0);
    expect(plan.strippedDead).toEqual([]);
  });
});
