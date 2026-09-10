import { describe, expect, it } from 'vitest';
import { computeStateOrder, findUnreachableStates } from '../../../src/modules/workflow/domain/workflow-ordering';

describe('workflow-ordering: computeStateOrder', () => {
  it('yields sequential orders 0,1,2,3 for a linear chain', () => {
    const order = computeStateOrder('open', [
      { from: 'open', to: 'in_progress' },
      { from: 'in_progress', to: 'resolved' },
      { from: 'resolved', to: 'closed' },
    ]);
    expect(order).not.toBeNull();
    expect(Object.fromEntries(order as Map<string, number | null>)).toEqual({
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
    ]) as Map<string, number | null>;
    expect(order).not.toBeNull();
    expect(order.get('A')).toBe(order.get('B'));
    expect(order.get('merged')).toBeGreaterThan(order.get('A') as number);
    expect(order.get('merged')).toBeGreaterThan(order.get('B') as number);
  });

  it('only nulls the states entangled in a mutual 2-state cycle (whole graph is that cycle)', () => {
    const order = computeStateOrder('open', [
      { from: 'open', to: 'in_progress' },
      { from: 'in_progress', to: 'open' },
    ]);
    expect(order.get('open')).toBeNull();
    expect(order.get('in_progress')).toBeNull();
  });

  it('does not flag a cycle when it only exists on a branch not reachable from initialState', () => {
    // 'open' -> 'closed' is a simple DAG; the unrelated 'X' <-> 'Y' cycle is not reachable from
    // 'open' and must not affect its ordering, nor appear (as null or otherwise) in the result
    // since findUnreachableStates/publish-time reachability validation handles orphaned states separately.
    const order = computeStateOrder('open', [
      { from: 'open', to: 'closed' },
      { from: 'X', to: 'Y' },
      { from: 'Y', to: 'X' },
    ]);
    expect(order).not.toBeNull();
    expect(Object.fromEntries(order as Map<string, number | null>)).toEqual({ open: 0, closed: 1 });
    expect(order.has('X')).toBe(false);
    expect(order.has('Y')).toBe(false);
  });

  it('only requires manual order for states entangled in a cycle, not the whole graph', () => {
    // graph: initial -> a -> b -> a (cycle a<->b), initial -> c (unrelated)
    const order = computeStateOrder('initial', [
      { from: 'initial', to: 'a' },
      { from: 'a', to: 'b' },
      { from: 'b', to: 'a' },
      { from: 'initial', to: 'c' },
    ]);
    expect(order.get('c')).toBe(1); // unrelated state still auto-ordered
    expect(order.get('a')).toBeNull(); // entangled in a cycle
    expect(order.get('b')).toBeNull();
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

  it('detects every member of overlapping/nested cycles via strongly-connected-component membership, not just gray-node back-edges (regression, review r3971557511)', () => {
    // Transitions A -> B, B -> A, A -> C, C -> B: a plain gray/black back-edge DFS starting at A
    // marks {A, B} as cyclic when it hits the B->A back-edge, but by the time it explores A->C,
    // B is already black, so C->B is never recognized as closing a cycle back into {A, B}. In
    // reality, A, B, and C are all mutually reachable (C -> B -> A -> C) and must all be null.
    const order = computeStateOrder('A', [
      { from: 'A', to: 'B' },
      { from: 'B', to: 'A' },
      { from: 'A', to: 'C' },
      { from: 'C', to: 'B' },
    ]);
    expect(order.get('A')).toBeNull();
    expect(order.get('B')).toBeNull();
    expect(order.get('C')).toBeNull();
  });

  it('does not null a state for a mere self-loop-free acyclic edge into an unrelated, separately-cyclic component', () => {
    // 'initial' -> 'a' -> 'b' -> 'a' (cycle a<->b) and 'initial' -> 'c' -> 'd' (separate acyclic
    // branch, no path back into the a/b cycle): only a and b are cyclic; c and d keep exact,
    // non-null topological distances.
    const order = computeStateOrder('initial', [
      { from: 'initial', to: 'a' },
      { from: 'a', to: 'b' },
      { from: 'b', to: 'a' },
      { from: 'initial', to: 'c' },
      { from: 'c', to: 'd' },
    ]);
    expect(order.get('a')).toBeNull();
    expect(order.get('b')).toBeNull();
    expect(order.get('c')).toBe(1);
    expect(order.get('d')).toBe(2);
  });

  it('nulls a single state with a direct self-loop even though its SCC has only one member', () => {
    const order = computeStateOrder('initial', [
      { from: 'initial', to: 'looping' },
      { from: 'looping', to: 'looping' },
    ]);
    expect(order.get('looping')).toBeNull();
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
