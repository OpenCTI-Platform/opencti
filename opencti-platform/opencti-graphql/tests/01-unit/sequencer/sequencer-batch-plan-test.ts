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
}) => {
  const intent = buildIntent({
    kind: args.kind,
    type: args.type ?? (args.kind === 'entity' ? 'Malware' : 'uses'),
    input: args.input ?? {},
    user: { id: 'u', origin: { applicant_id: 'conn1' } } as unknown as AuthUser,
    context: (args.context ?? {}) as unknown as AuthContext,
    opts: args.opts ?? {},
    candidateIds: args.candidateIds ?? [],
    referencedIds: args.referencedIds ?? [],
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

  it('breaks cycles by arrival order', () => {
    const report = intentOf({ kind: 'entity', type: 'Report', input: { objects: ['note--n'] }, candidateIds: ['report--r'], referencedIds: ['note--n'] });
    const note = intentOf({ kind: 'entity', type: 'Note', input: { objects: ['report--r'] }, candidateIds: ['note--n'], referencedIds: ['report--r'] });
    const plan = buildBatchPlan([report, note], noResolve);
    expect(plan.order.length).toBe(2);
    expect(plan.order[0].leader).toBe(report); // first arrived wins the cycle break
    expect(plan.parked).toEqual([]);
  });
});
