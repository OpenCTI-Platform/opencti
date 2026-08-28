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

// Workflow graphs are small (tens of states/transitions); this is a generous safety cap on the
// total number of longest-simple-path DFS visits, bounding the otherwise potentially-exponential
// exploration of a densely-connected graph.
const MAX_ORDERING_DFS_STEPS = 5000;

/**
 * Collects every state that lies on at least one cycle reachable from `initialState`, using a
 * white/gray/black DFS: a back-edge to a 'gray' node marks the whole stack segment as cyclic.
 */
const statesOnCycles = (initialState: string, adjacency: Map<string, Set<string>>): Set<string> => {
  const color = new Map<string, 'gray' | 'black'>();
  const stack: string[] = [];
  const onCycle = new Set<string>();

  const visit = (state: string) => {
    color.set(state, 'gray');
    stack.push(state);
    (adjacency.get(state) ?? new Set<string>()).forEach((neighbor) => {
      const neighborColor = color.get(neighbor);
      if (neighborColor === 'gray') {
        const ancestorIndex = stack.indexOf(neighbor);
        for (let i = ancestorIndex; i < stack.length; i += 1) {
          onCycle.add(stack[i]);
        }
      } else if (neighborColor === undefined) {
        visit(neighbor);
      }
    });
    stack.pop();
    color.set(state, 'black');
  };
  visit(initialState);
  return onCycle;
};

/**
 * Computes a display/validation order for every state reachable from `initialState`: the length
 * of the longest simple path from `initialState` to it.
 *
 * A state's value is `null` only if it lies on a cycle reachable from `initialState`, or if the
 * DFS never reached it before the step cap was hit. Callers must fall back to a manually supplied
 * `order` for any state whose value here is `null`.
 */
export const computeStateOrder = (
  initialState: string,
  transitions: OrderingTransition[],
  // Test-only injection point: lets unit tests deterministically exercise the step-cap fallback
  // without needing a graph large/deep enough to hit the real MAX_ORDERING_DFS_STEPS.
  maxSteps: number = MAX_ORDERING_DFS_STEPS,
): Map<string, number | null> => {
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

  const longestOrder = new Map<string, number>();
  let steps = 0;
  let capExceeded = false;
  const dfs = (state: string, depth: number, pathVisited: Set<string>) => {
    if (capExceeded) return;
    steps += 1;
    if (steps > maxSteps) {
      capExceeded = true;
      return;
    }
    const current = longestOrder.get(state);
    if (current === undefined || depth > current) {
      longestOrder.set(state, depth);
    }
    const neighbors = adjacency.get(state) ?? new Set<string>();
    neighbors.forEach((neighbor) => {
      if (capExceeded || pathVisited.has(neighbor)) return; // cycle back-edge on this path — stop this branch
      const nextVisited = new Set(pathVisited);
      nextVisited.add(neighbor);
      dfs(neighbor, depth + 1, nextVisited);
    });
  };
  dfs(initialState, 0, new Set([initialState]));

  const cyclicStates = statesOnCycles(initialState, adjacency);
  const result = new Map<string, number | null>();
  // A state is null only if it's cycle-entangled, or if the DFS never computed an order for it
  // (unreachable via any acyclic-terminating branch, or not yet visited when the step cap hit) —
  // states that did get a real value before the cap was hit elsewhere keep that value.
  reachable.forEach((state) => {
    result.set(state, (cyclicStates.has(state) || !longestOrder.has(state)) ? null : (longestOrder.get(state) as number));
  });
  return result;
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
