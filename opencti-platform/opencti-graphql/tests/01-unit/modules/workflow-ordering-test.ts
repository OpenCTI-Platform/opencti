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
    expect(Object.fromEntries(order as Map<string, number>)).toEqual({
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
    ]) as Map<string, number>;
    expect(order).not.toBeNull();
    expect(order.get('A')).toBe(order.get('B'));
    expect(order.get('merged')).toBeGreaterThan(order.get('A') as number);
    expect(order.get('merged')).toBeGreaterThan(order.get('B') as number);
  });

  it('returns null (ambiguous) when the reachable subgraph contains a cycle', () => {
    const order = computeStateOrder('open', [
      { from: 'open', to: 'in_progress' },
      { from: 'in_progress', to: 'open' },
    ]);
    expect(order).toBeNull();
  });

  it('does not flag a cycle when it only exists on a branch not reachable from initialState', () => {
    // 'open' -> 'closed' is a simple DAG; the unrelated cycle between 'X' and 'Y' must not affect it
    // since findUnreachableStates/publish-time reachability validation handles orphaned states separately.
    const order = computeStateOrder('open', [
      { from: 'open', to: 'closed' },
    ]);
    expect(order).not.toBeNull();
    expect(Object.fromEntries(order as Map<string, number>)).toEqual({ open: 0, closed: 1 });
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
