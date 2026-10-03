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
 * Runs a DFS from `initialState` over the reachable subgraph and returns every "back edge": an
 * edge that points to one of its own ancestors in the traversal (a state still `gray`, i.e. on
 * the current DFS stack — including a self-loop, since a state is trivially its own ancestor
 * while gray). Back edges are exactly the edges that close a cycle, however many cycles overlap
 * or nest: removing them always leaves an acyclic graph, since a depth-first traversal can never
 * reach one of its own ancestors through anything but a back edge.
 *
 * Edges are keyed as `${from}->${to}` since a state can appear as the source of both a back edge
 * and a regular edge.
 */
const findBackEdges = (
  initialState: string,
  reachable: Set<string>,
  adjacency: Map<string, Set<string>>,
): Set<string> => {
  const backEdges = new Set<string>();
  const status = new Map<string, 'gray' | 'black'>();

  const visit = (from: string) => {
    status.set(from, 'gray');
    (adjacency.get(from) ?? new Set<string>()).forEach((to) => {
      if (!reachable.has(to)) return; // edge leaves the reachable set (e.g. unreachable target)
      if (status.get(to) === 'gray') {
        backEdges.add(`${from}->${to}`);
      } else if (!status.has(to)) {
        visit(to);
      }
    });
    status.set(from, 'black');
  };

  visit(initialState);
  return backEdges;
};

/**
 * Computes a display/validation order for every state reachable from `initialState`: its
 * longest-path distance (counted in edges) from `initialState`.
 *
 * A cycle can never have every one of its edges strictly increasing (going around it always
 * leads back to a smaller value), so one edge per cycle — the "back edge" found by
 * `findBackEdges` — is left out of the distance computation. What remains is always a DAG, so a
 * standard topological longest-path (Kahn's algorithm + DP) gives every reachable state an
 * exact, deterministic value. There is no ambiguous case left to fall back to a manual order for.
 */
export const computeStateOrder = (
  initialState: string,
  transitions: OrderingTransition[],
): Map<string, number> => {
  const adjacency = buildAdjacency(transitions);

  // Reachability (BFS) over all states from initialState — cycles do not block reachability.
  const reachable = new Set<string>([initialState]);
  const bfsQueue: string[] = [initialState];
  while (bfsQueue.length > 0) {
    const current = bfsQueue.shift() as string;
    const neighbors = adjacency.get(current) ?? new Set<string>();
    neighbors.forEach((neighbor) => {
      if (!reachable.has(neighbor)) {
        reachable.add(neighbor);
        bfsQueue.push(neighbor);
      }
    });
  }

  const backEdges = findBackEdges(initialState, reachable, adjacency);
  const isUsableEdge = (from: string, to: string) => reachable.has(to) && !backEdges.has(`${from}->${to}`);

  // Kahn's algorithm: topologically sort the reachable states, ignoring back edges.
  const inDegree = new Map<string, number>();
  reachable.forEach((state) => inDegree.set(state, 0));
  reachable.forEach((from) => {
    (adjacency.get(from) ?? new Set<string>()).forEach((to) => {
      if (isUsableEdge(from, to)) inDegree.set(to, (inDegree.get(to) as number) + 1);
    });
  });

  const topoOrder: string[] = [];
  const remainingInDegree = new Map(inDegree);
  const queue: string[] = [];
  remainingInDegree.forEach((degree, state) => {
    if (degree === 0) queue.push(state);
  });
  while (queue.length > 0) {
    const current = queue.shift() as string;
    topoOrder.push(current);
    (adjacency.get(current) ?? new Set<string>()).forEach((next) => {
      if (!isUsableEdge(current, next)) return;
      const remaining = (remainingInDegree.get(next) as number) - 1;
      remainingInDegree.set(next, remaining);
      if (remaining === 0) queue.push(next);
    });
  }

  // Longest path (in edge count) from initialState, via DP over the topological order.
  const order = new Map<string, number>();
  order.set(initialState, 0);
  topoOrder.forEach((current) => {
    if (!order.has(current)) return; // not (yet) reached from initialState
    const distance = order.get(current) as number;
    (adjacency.get(current) ?? new Set<string>()).forEach((next) => {
      if (!isUsableEdge(current, next)) return;
      const candidate = distance + 1;
      if (!order.has(next) || candidate > (order.get(next) as number)) {
        order.set(next, candidate);
      }
    });
  });

  return order;
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
