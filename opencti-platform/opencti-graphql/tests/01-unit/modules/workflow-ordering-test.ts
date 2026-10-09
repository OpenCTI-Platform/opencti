import { describe, expect, it } from 'vitest';
import { computeStateOrder, findUnreachableStates } from '../../../src/modules/workflow/domain/workflow-ordering';

describe('workflow-ordering: computeStateOrder', () => {
  it('yields sequential orders 0,1,2,3 for a linear chain', () => {
    const order = computeStateOrder('open', [
      { from: 'open', to: 'in_progress' },
      { from: 'in_progress', to: 'resolved' },
      { from: 'resolved', to: 'closed' },
    ]);
    expect(Object.fromEntries(order)).toEqual({
      open: 0,
      in_progress: 1,
      resolved: 2,
      closed: 3,
    });
  });

  it('lets sibling branches share the same order value and sorts the merge point after both', () => {
    const order = computeStateOrder('open', [
      { from: 'open', to: 'A' },
      { from: 'open', to: 'B' },
      { from: 'A', to: 'merged' },
      { from: 'B', to: 'merged' },
    ]);
    expect(order.get('A')).toBe(order.get('B'));
    expect(order.get('merged')).toBeGreaterThan(order.get('A') as number);
    expect(order.get('merged')).toBeGreaterThan(order.get('B') as number);
  });

  it('gives sequential orders to a mutual 2-state cycle (whole graph is that cycle)', () => {
    // One edge of the cycle (in_progress -> open, found as a DFS back edge) is left out of the
    // distance computation, so the remaining open -> in_progress edge orders them normally.
    const order = computeStateOrder('open', [
      { from: 'open', to: 'in_progress' },
      { from: 'in_progress', to: 'open' },
    ]);
    expect(order.get('open')).toBe(0);
    expect(order.get('in_progress')).toBe(1);
  });

  it('does not flag a cycle when it only exists on a branch not reachable from initialState', () => {
    // 'open' -> 'closed' is a simple DAG; the unrelated 'X' <-> 'Y' cycle is not reachable from
    // 'open' and must not affect its ordering, nor appear in the result, since
    // findUnreachableStates/publish-time reachability validation handles orphaned states separately.
    const order = computeStateOrder('open', [
      { from: 'open', to: 'closed' },
      { from: 'X', to: 'Y' },
      { from: 'Y', to: 'X' },
    ]);
    expect(Object.fromEntries(order)).toEqual({ open: 0, closed: 1 });
    expect(order.has('X')).toBe(false);
    expect(order.has('Y')).toBe(false);
  });

  it('orders states entangled in a cycle sequentially too, not just the acyclic rest of the graph', () => {
    // graph: initial -> a -> b -> a (cycle a<->b), initial -> c (unrelated)
    const order = computeStateOrder('initial', [
      { from: 'initial', to: 'a' },
      { from: 'a', to: 'b' },
      { from: 'b', to: 'a' },
      { from: 'initial', to: 'c' },
    ]);
    expect(order.get('c')).toBe(1); // unrelated state, auto-ordered
    expect(order.get('a')).toBe(1); // entangled in a cycle, but still given an exact order
    expect(order.get('b')).toBe(2);
  });

  it('computes longest-simple-path length for acyclic graphs, matching prior BFS behavior on simple chains', () => {
    const order = computeStateOrder('initial', [
      { from: 'initial', to: 'a' },
      { from: 'a', to: 'b' },
    ]);
    expect(order.get('initial')).toBe(0);
    expect(order.get('a')).toBe(1);
    expect(order.get('b')).toBe(2);
  });

  it('uses the longest simple path when a node is reachable via branches of different length (path-scoped visited, not global)', () => {
    // initial -> A -> merged (length 2), and initial -> B -> C -> merged (length 3): the longer
    // branch must win. A global (rather than path-scoped) visited set would incorrectly freeze
    // merged's order at 2 once the first (shorter) branch reaches it.
    const order = computeStateOrder('initial', [
      { from: 'initial', to: 'A' },
      { from: 'A', to: 'merged' },
      { from: 'initial', to: 'B' },
      { from: 'B', to: 'C' },
      { from: 'C', to: 'merged' },
    ]);
    expect(order.get('merged')).toBe(3);
  });

  it('bounds the DFS with a step cap and does not hang on a densely-connected acyclic graph', () => {
    // Complete DAG on 15 nodes (edges i -> j for every i < j) has 2^13 simple paths from s0 to
    // s14 — far more than any reasonable step cap. The topological longest-path computation is
    // polynomial (no path enumeration, no cap), so it must still return promptly and, unlike the
    // old simple-path-enumeration approach, every value must be its exact longest-path length.
    const nodeCount = 15;
    const transitions = [];
    for (let i = 0; i < nodeCount; i += 1) {
      for (let j = i + 1; j < nodeCount; j += 1) {
        transitions.push({ from: `s${i}`, to: `s${j}` });
      }
    }
    const order = computeStateOrder('s0', transitions);
    expect(order.size).toBe(nodeCount);
    expect(Array.from(order.values()).every((value) => value !== null)).toBe(true);
    for (let i = 0; i < nodeCount; i += 1) {
      expect(order.get(`s${i}`)).toBe(i);
    }
  });

  it('computes exact topological order for every node of a dense DAG, not a step-cap-truncated approximation (regression, review r3971557516)', () => {
    // Same 15-node complete DAG: s2 has an edge to s3 (and to every higher-indexed node), so its
    // exact longest path from s0 must be 2, and s3's must be 3 — a path-enumeration approach with
    // a step cap previously returned s2 = s3 = 1 here once the cap was hit before their longest
    // paths were fully explored.
    const nodeCount = 15;
    const transitions = [];
    for (let i = 0; i < nodeCount; i += 1) {
      for (let j = i + 1; j < nodeCount; j += 1) {
        transitions.push({ from: `s${i}`, to: `s${j}` });
      }
    }
    const order = computeStateOrder('s0', transitions);
    expect(order.get('s2')).toBe(2);
    expect(order.get('s3')).toBe(3);
  });

  it('gives every member of overlapping/nested cycles an exact order, not just the acyclic rest of the graph (regression, review r3971557511)', () => {
    // Transitions A -> B, B -> A, A -> C, C -> B: A, B, and C are all mutually reachable
    // (C -> B -> A -> C). Only the back edge found by the DFS (B -> A) is left out of the
    // distance computation, so every state still gets an exact, deterministic order.
    const order = computeStateOrder('A', [
      { from: 'A', to: 'B' },
      { from: 'B', to: 'A' },
      { from: 'A', to: 'C' },
      { from: 'C', to: 'B' },
    ]);
    expect(order.get('A')).toBe(0);
    expect(order.get('C')).toBe(1);
    expect(order.get('B')).toBe(2);
  });

  it('orders a cyclic branch independently of an unrelated, separately-acyclic branch', () => {
    // 'initial' -> 'a' -> 'b' -> 'a' (cycle a<->b) and 'initial' -> 'c' -> 'd' (separate acyclic
    // branch, no path back into the a/b cycle): both branches get exact, deterministic orders.
    const order = computeStateOrder('initial', [
      { from: 'initial', to: 'a' },
      { from: 'a', to: 'b' },
      { from: 'b', to: 'a' },
      { from: 'initial', to: 'c' },
      { from: 'c', to: 'd' },
    ]);
    expect(order.get('a')).toBe(1);
    expect(order.get('b')).toBe(2);
    expect(order.get('c')).toBe(1);
    expect(order.get('d')).toBe(2);
  });

  it('gives a single state with a direct self-loop an exact order', () => {
    const order = computeStateOrder('initial', [
      { from: 'initial', to: 'looping' },
      { from: 'looping', to: 'looping' },
    ]);
    expect(order.get('looping')).toBe(1);
  });
});

describe('workflow-ordering: findUnreachableStates', () => {
  it('returns an empty array when every state is reachable from initialState', () => {
    const unreachable = findUnreachableStates('open', ['open', 'in_progress', 'closed'], [
      { from: 'open', to: 'in_progress' },
      { from: 'in_progress', to: 'closed' },
    ]);
    expect(unreachable).toEqual([]);
  });

  it('reports a state declared but never reachable from initialState', () => {
    const unreachable = findUnreachableStates('open', ['open', 'in_progress', 'orphan_state'], [
      { from: 'open', to: 'in_progress' },
    ]);
    expect(unreachable).toEqual(['orphan_state']);
  });

  it('does not report states reachable only via a cycle that is itself reachable', () => {
    const unreachable = findUnreachableStates('open', ['open', 'A', 'B'], [
      { from: 'open', to: 'A' },
      { from: 'A', to: 'B' },
      { from: 'B', to: 'A' },
    ]);
    expect(unreachable).toEqual([]);
  });
});
