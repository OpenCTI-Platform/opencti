import type { XYPosition } from 'reactflow';
import { orderLayers } from '../../../settings/sub_types/workflow/layout/order';
import { placeX } from '../../../settings/sub_types/workflow/layout/place';
import type { Graph, GraphEdge, GraphNode, LayerNode, RankedGraph, Segment } from '../../../settings/sub_types/workflow/layout/types';

// Deterministic layered layout of a playbook definition. Pure: no React, no store, no write.
// The same definition gives the same picture whatever the order of its nodes and links in the
// stored JSON: everything is first sorted by stable keys (the port order of the source
// component, then the node id), then ranked by longest path from the entry point, ordered by
// barycenter sweeps (crossing reduction shared with the workflow editor) and placed.

export type PlaybookLayoutMode = 'vertical' | 'horizontal' | 'manual';

export const PLAYBOOK_LAYOUT_MODES: PlaybookLayoutMode[] = ['vertical', 'horizontal', 'manual'];

export interface PlaybookLayoutNode {
  id: string;
  component_id: string;
  position?: XYPosition | null;
}

export interface PlaybookLayoutLink {
  id: string;
  from: { id: string; port: string };
  to: { id: string };
}

export interface PlaybookLayoutComponent {
  id: string;
  is_entry_point?: boolean | null;
  ports?: ReadonlyArray<{ id: string; type: string }> | null;
}

export interface PlaybookLayoutOptions {
  mode: PlaybookLayoutMode;
  nodeSize?: { width: number; height: number };
  // [gap between siblings, gap between ranks], in pixels
  spacing?: [number, number];
}

export interface PlaybookLayoutResult {
  positions: Map<string, XYPosition>; // top-left corner, React Flow convention
  routes: Map<string, XYPosition[]>; // link id -> bend points between source and target (may be empty)
  ranks: Map<string, number>;
  crossings: number;
}

export const PLAYBOOK_NODE_SIZE = { width: 300, height: 96 };
const DEFAULT_SPACING: [number, number] = [48, 72];

const compareStrings = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

const portIndex = (components: Map<string, PlaybookLayoutComponent>, node: PlaybookLayoutNode | undefined, port: string) => {
  const ports = (node && components.get(node.component_id)?.ports) || [];
  const outs = ports.filter((p) => p.type === 'out');
  // A component not in the catalog has no port list: 'out' first, the other ports after it
  // (then by name, below), the order its card draws them in.
  if (outs.length === 0) return port === 'out' ? 0 : 1;
  const index = outs.findIndex((p) => p.id === port);
  return index === -1 ? outs.length : index;
};

// Canonical order: a depth-first walk from the root, children visited by the port order of
// their parent's component, then by node id. Nodes the walk never reaches (a legacy
// definition) follow, sorted by id. The array order of the stored JSON is never read.
export const canonicalOrder = (
  nodes: PlaybookLayoutNode[],
  links: PlaybookLayoutLink[],
  components: Map<string, PlaybookLayoutComponent>,
): { nodes: PlaybookLayoutNode[]; links: PlaybookLayoutLink[] } => {
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const validLinks = links.filter((l) => byId.has(l.from?.id) && byId.has(l.to?.id));
  const sortedLinks = validLinks.slice().sort((a, b) => compareStrings(a.from.id, b.from.id)
    || portIndex(components, byId.get(a.from.id), a.from.port) - portIndex(components, byId.get(b.from.id), b.from.port)
    || compareStrings(a.from.port, b.from.port)
    || compareStrings(a.to.id, b.to.id)
    || compareStrings(a.id, b.id));
  const outgoing = new Map<string, PlaybookLayoutLink[]>();
  const incoming = new Map<string, number>();
  sortedLinks.forEach((l) => {
    if (!outgoing.has(l.from.id)) outgoing.set(l.from.id, []);
    outgoing.get(l.from.id)!.push(l);
    incoming.set(l.to.id, (incoming.get(l.to.id) ?? 0) + 1);
  });
  const sortedIds = nodes.map((n) => n.id).sort(compareStrings);
  const roots = sortedIds
    .filter((id) => !incoming.has(id))
    .sort((a, b) => Number(!components.get(byId.get(a)!.component_id)?.is_entry_point)
      - Number(!components.get(byId.get(b)!.component_id)?.is_entry_point) || compareStrings(a, b));
  const order: string[] = [];
  const seen = new Set<string>();
  const walk = (start: string) => {
    const stack = [start];
    while (stack.length) {
      const id = stack.pop()!;
      if (seen.has(id)) continue;
      seen.add(id);
      order.push(id);
      const children = (outgoing.get(id) ?? []).map((l) => l.to.id);
      for (let i = children.length - 1; i >= 0; i -= 1) {
        if (!seen.has(children[i])) stack.push(children[i]);
      }
    }
  };
  roots.forEach(walk);
  sortedIds.forEach(walk);
  const rankOf = new Map(order.map((id, i) => [id, i]));
  const orderedLinks = sortedLinks.slice().sort((a, b) => rankOf.get(a.from.id)! - rankOf.get(b.from.id)!
    || portIndex(components, byId.get(a.from.id), a.from.port) - portIndex(components, byId.get(b.from.id), b.from.port)
    || compareStrings(a.from.port, b.from.port)
    || rankOf.get(a.to.id)! - rankOf.get(b.to.id)!
    || compareStrings(a.id, b.id));
  return { nodes: order.map((id) => byId.get(id)!), links: orderedLinks };
};

// Count the crossings of a laid-out picture (straight segments between consecutive points).
export const countCrossings = (result: PlaybookLayoutResult, links: PlaybookLayoutLink[], size = PLAYBOOK_NODE_SIZE, mode: PlaybookLayoutMode = 'vertical') => {
  const horizontal = mode === 'horizontal';
  const centre = (id: string, out: boolean): XYPosition => {
    const p = result.positions.get(id)!;
    if (horizontal) return { x: p.x + (out ? size.width : 0), y: p.y + size.height / 2 };
    return { x: p.x + size.width / 2, y: p.y + (out ? size.height : 0) };
  };
  const segments: [XYPosition, XYPosition, string][] = [];
  links.forEach((l) => {
    if (!result.positions.has(l.from.id) || !result.positions.has(l.to.id)) return;
    const points = [centre(l.from.id, true), ...(result.routes.get(l.id) ?? []), centre(l.to.id, false)];
    for (let i = 0; i + 1 < points.length; i += 1) segments.push([points[i], points[i + 1], l.id]);
  });
  const orient = (a: XYPosition, b: XYPosition, c: XYPosition) => Math.sign((b.x - a.x) * (c.y - a.y) - (b.y - a.y) * (c.x - a.x));
  let crossings = 0;
  for (let i = 0; i < segments.length; i += 1) {
    for (let j = i + 1; j < segments.length; j += 1) {
      const [p1, p2, a] = segments[i];
      const [p3, p4, b] = segments[j];
      if (a === b) continue;
      const shared = [p1, p2].some((p) => [p3, p4].some((q) => Math.abs(p.x - q.x) < 0.5 && Math.abs(p.y - q.y) < 0.5));
      if (shared) continue;
      if (orient(p1, p2, p3) * orient(p1, p2, p4) < 0 && orient(p3, p4, p1) * orient(p3, p4, p2) < 0) crossings += 1;
    }
  }
  return crossings;
};

export const layoutPlaybook = (
  definitionNodes: PlaybookLayoutNode[],
  definitionLinks: PlaybookLayoutLink[],
  componentList: ReadonlyArray<PlaybookLayoutComponent | null | undefined>,
  options: PlaybookLayoutOptions,
): PlaybookLayoutResult => {
  const result: PlaybookLayoutResult = { positions: new Map(), routes: new Map(), ranks: new Map(), crossings: 0 };
  if (definitionNodes.length === 0) return result;
  const size = options.nodeSize ?? PLAYBOOK_NODE_SIZE;
  const components = new Map<string, PlaybookLayoutComponent>();
  componentList.forEach((c) => {
    if (c) components.set(c.id, c);
  });
  const { nodes, links } = canonicalOrder(definitionNodes, definitionLinks, components);

  // Manual mode keeps the saved positions; a node without one falls back to the vertical layout.
  if (options.mode === 'manual') {
    const fallback = layoutPlaybook(definitionNodes, definitionLinks, componentList, { ...options, mode: 'vertical' });
    nodes.forEach((n) => {
      const saved = n.position;
      const valid = saved && Number.isFinite(saved.x) && Number.isFinite(saved.y);
      result.positions.set(n.id, valid ? { x: saved.x, y: saved.y } : fallback.positions.get(n.id)!);
      result.ranks.set(n.id, fallback.ranks.get(n.id)!);
    });
    return result;
  }

  const horizontal = options.mode === 'horizontal';
  const [gapSibling, gapRank] = options.spacing ?? DEFAULT_SPACING;
  // The layered core works top-down; the horizontal mode swaps the axes at the end.
  const breadth = horizontal ? size.height : size.width;
  const depth = horizontal ? size.width : size.height;

  const graphNodes = new Map<string, GraphNode>();
  nodes.forEach((n, order) => graphNodes.set(n.id, { id: n.id, type: 'node', w: breadth, h: depth, order }));
  const edges: GraphEdge[] = links.map((l, order) => ({ id: l.id, source: l.from.id, target: l.to.id, order }));
  const outE = new Map<string, GraphEdge[]>();
  const inE = new Map<string, GraphEdge[]>();
  nodes.forEach((n) => {
    outE.set(n.id, []);
    inE.set(n.id, []);
  });
  edges.forEach((e) => {
    outE.get(e.source)!.push(e);
    inE.get(e.target)!.push(e);
  });
  const graph: Graph = { nodes: graphNodes, list: [...graphNodes.values()], edges, outE, inE, maxHeight: depth };

  // Cycles never pass the backend invariant; a legacy one is broken at the edge closing it.
  const backEdges = new Set<string>();
  const state = new Map<string, 'open' | 'done'>();
  graph.list.forEach((start) => {
    if (state.has(start.id)) return;
    const stack = [{ id: start.id, next: 0 }];
    state.set(start.id, 'open');
    while (stack.length) {
      const frame = stack[stack.length - 1];
      const out = outE.get(frame.id)!;
      if (frame.next < out.length) {
        const e = out[frame.next];
        frame.next += 1;
        const s = state.get(e.target);
        if (s === 'open') backEdges.add(e.id);
        else if (!s) {
          state.set(e.target, 'open');
          stack.push({ id: e.target, next: 0 });
        }
      } else {
        state.set(frame.id, 'done');
        stack.pop();
      }
    }
  });
  const forwardEdges = edges.filter((e) => !backEdges.has(e.id) && e.source !== e.target);
  const fOut = new Map<string, GraphEdge[]>();
  const fIn = new Map<string, GraphEdge[]>();
  nodes.forEach((n) => {
    fOut.set(n.id, []);
    fIn.set(n.id, []);
  });
  forwardEdges.forEach((e) => {
    fOut.get(e.source)!.push(e);
    fIn.get(e.target)!.push(e);
  });
  // Longest path from the entry point, in canonical topological order.
  const indegree = new Map(nodes.map((n) => [n.id, fIn.get(n.id)!.length]));
  const queue = nodes.filter((n) => indegree.get(n.id) === 0).map((n) => n.id);
  const rank = new Map<string, number>();
  while (queue.length) {
    const id = queue.shift()!;
    let r = 0;
    fIn.get(id)!.forEach((e) => {
      r = Math.max(r, rank.get(e.source)! + 1);
    });
    rank.set(id, r);
    fOut.get(id)!.forEach((e) => {
      indegree.set(e.target, indegree.get(e.target)! - 1);
      if (indegree.get(e.target) === 0) queue.push(e.target);
    });
  }

  const layered = new Map<string, LayerNode>();
  nodes.forEach((n) => layered.set(n.id, { id: n.id, rank: rank.get(n.id)!, w: breadth, h: depth, dummy: false }));
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
  const ranked: RankedGraph = {
    backEdges,
    backwardTransitions: new Set(),
    forwardEdges,
    fOut,
    fIn,
    rank,
    layered,
    chains,
    segments,
    up,
    down,
    maxRank,
  };
  const ordering = orderLayers(graph, ranked);
  const x = placeX(ranked, ordering, gapSibling);
  const pitch = depth + gapRank;
  const toFlow = (cx: number, r: number, w: number, h: number): XYPosition => {
    // Whole pixels: a card, its ports and the links that reach them share one integer line.
    const along = Math.round(r * pitch);
    if (horizontal) return { x: along, y: Math.round(cx - h / 2) };
    return { x: Math.round(cx - w / 2), y: along };
  };
  nodes.forEach((n) => {
    result.positions.set(n.id, toFlow(x.get(n.id)!, rank.get(n.id)!, size.width, size.height));
    result.ranks.set(n.id, rank.get(n.id)!);
  });
  links.forEach((l) => {
    const chain = chains.get(l.id);
    const bends = (chain ?? []).slice(1, -1).map((d) => {
      const r = layered.get(d)!.rank;
      const along = r * pitch + depth / 2;
      return horizontal ? { x: along, y: x.get(d)! } : { x: x.get(d)!, y: along };
    });
    result.routes.set(l.id, bends);
  });
  result.crossings = ordering.crossings;
  return result;
};
