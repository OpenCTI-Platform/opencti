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
 * Groups states into "clusters" where every state can reach every other state in the same
 * cluster (Tarjan's algorithm). Returns a Map from each vertex to its cluster id.
 *
 * A single gray/black DFS can miss cycles that close through an already-visited node (e.g.
 * A->B, B->A, A->C, C->B: C closes the loop back to A via B, but a plain back-edge check only
 * looks at the current DFS stack, so it never revisits the already-black B). This algorithm
 * catches those cases too.
 */
const computeStronglyConnectedComponents = (
  vertices: Set<string>,
  adjacency: Map<string, Set<string>>,
): Map<string, number> => {
  let counter = 0;
  const indices = new Map<string, number>();
  const lowlink = new Map<string, number>();
  const onStack = new Set<string>();
  const stack: string[] = [];
  const componentOf = new Map<string, number>();
  let componentCount = 0;

  const strongConnect = (v: string) => {
    indices.set(v, counter);
    lowlink.set(v, counter);
    counter += 1;
    stack.push(v);
    onStack.add(v);

    (adjacency.get(v) ?? new Set<string>()).forEach((w) => {
      if (!vertices.has(w)) return; // edge leaves the considered vertex set (e.g. unreachable target)
      if (!indices.has(w)) {
        strongConnect(w);
        lowlink.set(v, Math.min(lowlink.get(v) as number, lowlink.get(w) as number));
      } else if (onStack.has(w)) {
        lowlink.set(v, Math.min(lowlink.get(v) as number, indices.get(w) as number));
      }
    });

    if (lowlink.get(v) === indices.get(v)) {
      // v is the root of an SCC — pop the stack to collect all of its members.
      let w: string;
      do {
        w = stack.pop() as string;
        onStack.delete(w);
        componentOf.set(w, componentCount);
      } while (w !== v);
      componentCount += 1;
    }
  };

  vertices.forEach((v) => {
    if (!indices.has(v)) strongConnect(v);
  });

  return componentOf;
};

/**
 * Collects every state in `vertices` that lies on at least one cycle: either its SCC has more
 * than one member, or it has a direct self-loop (a single-member SCC is otherwise acyclic).
 */
const statesOnCycles = (
  vertices: Set<string>,
  adjacency: Map<string, Set<string>>,
  componentOf: Map<string, number>,
): Set<string> => {
  const componentSizes = new Map<number, number>();
  componentOf.forEach((component) => {
    componentSizes.set(component, (componentSizes.get(component) ?? 0) + 1);
  });

  const onCycle = new Set<string>();
  vertices.forEach((state) => {
    const component = componentOf.get(state) as number;
    const hasSelfLoop = (adjacency.get(state) ?? new Set<string>()).has(state);
    if ((componentSizes.get(component) as number) > 1 || hasSelfLoop) {
      onCycle.add(state);
    }
  });
  return onCycle;
};

/**
 * Computes a display/validation order for every state reachable from `initialState`: its
 * topological distance (longest path, counted in edges of the SCC-condensation graph) from
 * `initialState`.
 *
 * A state's value is `null` only if it lies on a cycle reachable from `initialState` — every
 * other reachable state gets a well-defined, exact value, computed via topological longest-path
 * DP over the (always-acyclic) SCC condensation rather than by enumerating simple paths, so
 * there is no step cap and no risk of an incomplete/non-final value being returned. Callers must
 * fall back to a manually supplied `order` for any state whose value here is `null`.
 */
export const computeStateOrder = (
  initialState: string,
  transitions: OrderingTransition[],
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

  const componentOf = computeStronglyConnectedComponents(reachable, adjacency);
  const cyclicStates = statesOnCycles(reachable, adjacency, componentOf);

  // Shrink each cycle down to one node — what's left is always a DAG, ready for a topological sort.
  const condensationAdjacency = new Map<number, Set<number>>();
  const inDegree = new Map<number, number>();
  reachable.forEach((state) => {
    const fromComponent = componentOf.get(state) as number;
    if (!inDegree.has(fromComponent)) inDegree.set(fromComponent, 0);
    (adjacency.get(state) ?? new Set<string>()).forEach((neighbor) => {
      if (!reachable.has(neighbor)) return;
      const toComponent = componentOf.get(neighbor) as number;
      if (toComponent === fromComponent) return;
      if (!condensationAdjacency.has(fromComponent)) condensationAdjacency.set(fromComponent, new Set());
      const edges = condensationAdjacency.get(fromComponent) as Set<number>;
      if (!edges.has(toComponent)) {
        edges.add(toComponent);
        inDegree.set(toComponent, (inDegree.get(toComponent) ?? 0) + 1);
      }
    });
  });

  // Kahn's algorithm: topologically sort the condensation graph.
  const topoOrder: number[] = [];
  const remainingInDegree = new Map(inDegree);
  const queue: number[] = [];
  remainingInDegree.forEach((degree, component) => {
    if (degree === 0) queue.push(component);
  });
  while (queue.length > 0) {
    const component = queue.shift() as number;
    topoOrder.push(component);
    (condensationAdjacency.get(component) ?? new Set<number>()).forEach((next) => {
      const remaining = (remainingInDegree.get(next) as number) - 1;
      remainingInDegree.set(next, remaining);
      if (remaining === 0) queue.push(next);
    });
  }

  // Longest path (in edge count) from initialState's component, via DP over the topological order.
  const initialComponent = componentOf.get(initialState) as number;
  const componentDistance = new Map<number, number>();
  componentDistance.set(initialComponent, 0);
  topoOrder.forEach((component) => {
    if (!componentDistance.has(component)) return; // not (yet) reached from initialState's component
    const distance = componentDistance.get(component) as number;
    (condensationAdjacency.get(component) ?? new Set<number>()).forEach((next) => {
      const candidate = distance + 1;
      if (!componentDistance.has(next) || candidate > (componentDistance.get(next) as number)) {
        componentDistance.set(next, candidate);
      }
    });
  });

  const result = new Map<string, number | null>();
  reachable.forEach((state) => {
    if (cyclicStates.has(state)) {
      result.set(state, null);
      return;
    }
    const component = componentOf.get(state) as number;
    result.set(state, componentDistance.get(component) ?? null);
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
