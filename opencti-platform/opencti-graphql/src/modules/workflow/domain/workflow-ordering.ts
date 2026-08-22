/**
 * Pure graph helpers used to derive a display/validation order for workflow states
 * from the transition graph, without requiring an explicit manual `order` on every state.
 */

interface OrderingTransition {
  from: string | string[] | null;
  to: string | null;
}

const buildAdjacency = (transitions: OrderingTransition[]): Map<string, Set<string>> => {
  const adjacency = new Map<string, Set<string>>();
  const addEdge = (from: string, to: string) => {
    if (!adjacency.has(from)) adjacency.set(from, new Set());
    (adjacency.get(from) as Set<string>).add(to);
  };
  transitions.forEach((transition) => {
    if (transition.from === null || transition.to === null || transition.to === '*') {
      return;
    }
    const fromStates = Array.isArray(transition.from) ? transition.from : [transition.from];
    fromStates.forEach((from) => {
      if (from && from !== '*') {
        addEdge(from, transition.to as string);
      }
    });
  });
  return adjacency;
};

/**
 * Computes a display/validation order for every state reachable from `initialState`, using
 * BFS shortest-path depth (sibling branches that reconverge legitimately share the same order value).
 *
 * Returns `null` when the reachable subgraph contains a cycle — in that case no single BFS depth
 * can represent a meaningful order, and callers must fall back to a manually supplied `order` per state.
 */
export const computeStateOrder = (
  initialState: string,
  transitions: OrderingTransition[],
): Map<string, number> | null => {
  const adjacency = buildAdjacency(transitions);

  // BFS shortest-path depth from initialState over all reachable states.
  const order = new Map<string, number>();
  order.set(initialState, 0);
  const queue: string[] = [initialState];
  while (queue.length > 0) {
    const current = queue.shift() as string;
    const depth = order.get(current) as number;
    const neighbors = adjacency.get(current) ?? new Set<string>();
    neighbors.forEach((neighbor) => {
      if (!order.has(neighbor)) {
        order.set(neighbor, depth + 1);
        queue.push(neighbor);
      }
    });
  }

  // Cycle detection restricted to the reachable subgraph (white/gray/black DFS coloring).
  const WHITE = 0;
  const GRAY = 1;
  const BLACK = 2;
  const color = new Map<string, number>();
  order.forEach((_, state) => color.set(state, WHITE));
  let hasCycle = false;
  const visit = (state: string) => {
    if (hasCycle) return;
    color.set(state, GRAY);
    const neighbors = adjacency.get(state) ?? new Set<string>();
    neighbors.forEach((neighbor) => {
      if (!order.has(neighbor)) return; // not part of the reachable subgraph
      const neighborColor = color.get(neighbor);
      if (neighborColor === GRAY) {
        hasCycle = true;
      } else if (neighborColor === WHITE) {
        visit(neighbor);
      }
    });
    color.set(state, BLACK);
  };
  order.forEach((_, state) => {
    if (color.get(state) === WHITE) visit(state);
  });

  return hasCycle ? null : order;
};

/**
 * Returns the subset of `allStates` that cannot be reached from `initialState` via any transition
 * path (excluding `initialState` itself). Reachability here is independent of cycles: a state
 * inside a cycle it can be entered from is still reachable and is not reported.
 */
export const findUnreachableStates = (
  initialState: string,
  allStates: string[],
  transitions: OrderingTransition[],
): string[] => {
  const adjacency = buildAdjacency(transitions);
  const reachable = new Set<string>([initialState]);
  const stack: string[] = [initialState];
  while (stack.length > 0) {
    const current = stack.pop() as string;
    const neighbors = adjacency.get(current) ?? new Set<string>();
    neighbors.forEach((neighbor) => {
      if (!reachable.has(neighbor)) {
        reachable.add(neighbor);
        stack.push(neighbor);
      }
    });
  }
  return allStates.filter((state) => !reachable.has(state));
};
