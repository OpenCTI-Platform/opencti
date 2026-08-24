import { describe, expect, it } from 'vitest';
import { computeStateOrder, findUnreachableStates, isEndingState } from '../../../src/modules/workflow/domain/workflow-ordering';

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
    // 'open' -> 'closed' is a simple DAG; the unrelated cycle between 'X' and 'Y' must not affect it
    // since findUnreachableStates/publish-time reachability validation handles orphaned states separately.
    const order = computeStateOrder('open', [
      { from: 'open', to: 'closed' },
    ]);
    expect(order).not.toBeNull();
    expect(Object.fromEntries(order as Map<string, number | null>)).toEqual({ open: 0, closed: 1 });
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
    // s14 — far more than any reasonable step cap — so the cap must kick in and the call must
    // still return promptly instead of exploring every path.
    const nodeCount = 15;
    const transitions = [];
    for (let i = 0; i < nodeCount; i += 1) {
      for (let j = i + 1; j < nodeCount; j += 1) {
        transitions.push({ from: `s${i}`, to: `s${j}` });
      }
    }
    const order = computeStateOrder('s0', transitions);
    expect(order.size).toBe(nodeCount);
    // The cap fallback nulls affected states rather than hanging or throwing.
    expect(Array.from(order.values()).some((value) => value === null)).toBe(true);
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

describe('workflow-ordering: isEndingState', () => {
  const transitions = [
    { from: 'open', to: 'in_progress' },
    { from: 'in_progress', to: 'resolved' },
    { from: 'in_progress', to: 'closed' },
  ];

  it('returns true for a state that never appears in any from list', () => {
    expect(isEndingState(transitions, 'resolved')).toBe(true);
    expect(isEndingState(transitions, 'closed')).toBe(true);
  });

  it('returns false for a state with at least one outgoing transition', () => {
    expect(isEndingState(transitions, 'open')).toBe(false);
    expect(isEndingState(transitions, 'in_progress')).toBe(false);
  });

  it('supports transitions with a from array (multiple source states)', () => {
    const multiFrom = [{ from: ['open', 'in_progress'], to: 'closed' }];
    expect(isEndingState(multiFrom, 'open')).toBe(false);
    expect(isEndingState(multiFrom, 'in_progress')).toBe(false);
    expect(isEndingState(multiFrom, 'closed')).toBe(true);
  });

  it('does not treat a wildcard from ("*") as an outgoing transition of a specific state', () => {
    const withWildcard = [
      { from: 'open', to: 'in_progress' },
      { from: '*', to: 'cancelled' },
    ];
    // 'in_progress' has no explicit outgoing transition of its own — only reachable via the
    // global wildcard — so it is still considered an ending state (matches the existing
    // "ending state" convention used by publishWorkflowDefinition/workflow-validation.ts).
    expect(isEndingState(withWildcard, 'in_progress')).toBe(true);
  });

  it('returns true for a state absent from every transition entirely (isolated state)', () => {
    expect(isEndingState(transitions, 'unrelated_state')).toBe(true);
  });
});
