import { NODE_SIZE, WorkflowNodeType } from '../utils';
import type { Graph, GraphEdge, GraphNode, LayerNode, LayoutInputEdge, LayoutInputNode, RankedGraph, Segment } from './types';

export const buildGraph = (inputNodes: LayoutInputNode[], inputEdges: LayoutInputEdge[]): Graph => {
  const nodes = new Map<string, GraphNode>();
  inputNodes.forEach((n, order) => {
    nodes.set(n.id, {
      id: n.id,
      type: n.type ?? WorkflowNodeType.status,
      w: n.width || NODE_SIZE.width,
      h: n.height || NODE_SIZE.height,
      order,
    });
  });
  const edges: GraphEdge[] = [];
  inputEdges.forEach((e, order) => {
    if (nodes.has(e.source) && nodes.has(e.target)) {
      edges.push({ id: e.id, source: e.source, target: e.target, order });
    }
  });
  const outE = new Map<string, GraphEdge[]>();
  const inE = new Map<string, GraphEdge[]>();
  nodes.forEach((_, id) => {
    outE.set(id, []);
    inE.set(id, []);
  });
  edges.forEach((e) => {
    outE.get(e.source)!.push(e);
    inE.get(e.target)!.push(e);
  });
  const list = [...nodes.values()];
  const maxHeight = list.length ? Math.max(...list.map((n) => n.h)) : NODE_SIZE.height;
  return { nodes, list, edges, outE, inE, maxHeight };
};

// Phase 1: cycle breaking. DFS from the initial status (the saved one while it is on the canvas,
// else the first status without incoming edge: the same rule as transformToWorkflowDefinition),
// following outgoing edges in model order. An edge reaching a node still on the DFS stack is a
// back edge, and so is every edge into the initial status, so that nothing is drawn above it.
const findBackEdges = (graph: Graph, initialStatusId?: string | null): Set<string> => {
  const state = new Map<string, 'open' | 'done'>();
  const backEdges = new Set<string>();
  // Iterative so a long chain of statuses cannot overflow the call stack.
  const dfs = (start: string) => {
    const stack = [{ id: start, next: 0 }];
    state.set(start, 'open');
    while (stack.length) {
      const frame = stack[stack.length - 1];
      const out = graph.outE.get(frame.id)!;
      if (frame.next < out.length) {
        const e = out[frame.next];
        frame.next += 1;
        const s = state.get(e.target);
        if (s === 'open') {
          backEdges.add(e.id);
        } else if (!s) {
          state.set(e.target, 'open');
          stack.push({ id: e.target, next: 0 });
        }
      } else {
        state.set(frame.id, 'done');
        stack.pop();
      }
    }
  };
  const visit = (n: GraphNode) => {
    if (!state.has(n.id)) dfs(n.id);
  };
  const statuses = graph.list.filter((n) => n.type === WorkflowNodeType.status);
  const initial = initialStatusId ? graph.nodes.get(initialStatusId) : undefined;
  if (initial) {
    graph.inE.get(initial.id)!.forEach((e) => backEdges.add(e.id));
    visit(initial);
  }
  statuses.filter((n) => graph.inE.get(n.id)!.length === 0).forEach(visit);
  statuses.forEach(visit);
  graph.list.forEach(visit);
  return backEdges;
};

// Phase 2: longest-path ranks on the forward graph. Statuses take even rows, transitions and
// placeholders odd rows. Edges spanning several rows get one dummy per crossed row.
export const rankGraph = (graph: Graph, initialStatusId?: string | null): RankedGraph => {
  const backEdges = findBackEdges(graph, initialStatusId);
  // A transition goes into a side lane only when every outgoing edge closes a cycle. One that
  // also leads forward stays in the flow; its backward edges get edge lanes.
  const backwardTransitions = new Set(graph.list
    .filter((n) => {
      const out = graph.outE.get(n.id)!;
      return n.type === WorkflowNodeType.transition && out.length > 0 && out.every((e) => backEdges.has(e.id));
    })
    .map((n) => n.id));
  const forward = graph.list.filter((n) => !backwardTransitions.has(n.id));
  const forwardEdges = graph.edges.filter((e) => !backEdges.has(e.id)
    && !backwardTransitions.has(e.source) && !backwardTransitions.has(e.target));
  const fOut = new Map<string, GraphEdge[]>();
  const fIn = new Map<string, GraphEdge[]>();
  forward.forEach((n) => {
    fOut.set(n.id, []);
    fIn.set(n.id, []);
  });
  forwardEdges.forEach((e) => {
    fOut.get(e.source)!.push(e);
    fIn.get(e.target)!.push(e);
  });

  const indegree = new Map(forward.map((n) => [n.id, fIn.get(n.id)!.length]));
  const queue = forward.filter((n) => indegree.get(n.id) === 0).map((n) => n.id);
  const topo: string[] = [];
  while (queue.length) {
    const id = queue.shift()!;
    topo.push(id);
    fOut.get(id)!.forEach((e) => {
      indegree.set(e.target, indegree.get(e.target)! - 1);
      if (indegree.get(e.target) === 0) queue.push(e.target);
    });
  }
  const rank = new Map<string, number>();
  topo.forEach((id) => {
    let r = 0;
    fIn.get(id)!.forEach((e) => {
      r = Math.max(r, rank.get(e.source)! + 1);
    });
    const wantsEven = graph.nodes.get(id)!.type === WorkflowNodeType.status;
    if ((r % 2 === 0) !== wantsEven) r += 1;
    rank.set(id, r);
  });

  const layered = new Map<string, LayerNode>();
  forward.forEach((n) => layered.set(n.id, { id: n.id, rank: rank.get(n.id)!, w: n.w, h: n.h, dummy: false }));
  const chains = new Map<string, string[]>();
  const segments: Segment[] = [];
  forwardEdges.forEach((e) => {
    const chain = [e.source];
    for (let r = rank.get(e.source)! + 1; r < rank.get(e.target)!; r += 1) {
      const dummyId = `__dummy:${e.id}:${r}`;
      layered.set(dummyId, { id: dummyId, rank: r, w: 0, h: 0, dummy: true });
      chain.push(dummyId);
    }
    chain.push(e.target);
    chains.set(e.id, chain);
    for (let i = 0; i + 1 < chain.length; i += 1) segments.push({ u: chain[i], v: chain[i + 1] });
  });
  const up = new Map<string, string[]>();
  const down = new Map<string, string[]>();
  layered.forEach((n) => {
    up.set(n.id, []);
    down.set(n.id, []);
  });
  segments.forEach((s) => {
    down.get(s.u)!.push(s.v);
    up.get(s.v)!.push(s.u);
  });
  const maxRank = Math.max(0, ...[...layered.values()].map((n) => n.rank));
  return { backEdges, backwardTransitions, forwardEdges, fOut, fIn, rank, layered, chains, segments, up, down, maxRank };
};
