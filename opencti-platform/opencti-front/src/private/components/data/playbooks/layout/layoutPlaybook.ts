import type { XYPosition } from 'reactflow';
import { orderLayers } from '../../../settings/sub_types/workflow/layout/order';
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
  // Offset of the out port `index` of `count` from the card centre, across the flow (x when
  // vertical, y when horizontal). Defaults to ports spread evenly over the card breadth.
  portOffset?: (index: number, count: number) => number;
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

// Straight links within a compact band (Sam, 19 Nov 2026: "compact, no drift ... we should do our
// best to have links straight, but of course, layout first and no drift. Be smart").
// 1. Hard constraints: the gap between siblings and every centre inside one band as wide as the widest
//    rank plus a quarter card (one port offset). A chain of steps therefore never drifts: the width of
//    the picture is the width of its widest rank, whatever the depth.
// 2. Within them, a bounded beam search over the ranks, top-down, maximises the score of the picture:
//    straight links first (the child's input under the port that feeds it), minus a crossing penalty,
//    then the shortest elbows. For each kept picture of the ranks above, a rank tries its orders (the
//    crossing-reduced order, plus the permutations of a small rank that keep the port order of every
//    parent) and, for each node, the positions that make one of the links of the rank straight; the
//    positions are then packed into the band. Links only join consecutive ranks (long links go through
//    dummies), so a picture is summed up by its last rank: the search keeps the best BEAM of them.
//    Deterministic: every candidate list is built in a fixed order and ties break on the elbow length,
//    then on the order the candidates were generated in.
interface StraightLink { id: string; chain: string[]; offset: number }

const BEAM = 16;
// Sam's order (19 Nov 2026): straight links first, then short elbows, then few crossings. A crossing
// costs half a straight link, so a straight link wins over a crossing and two crossings cancel it.
const CROSSING_PENALTY = 0.5;
const MAX_PERMUTED_RANK = 4;
const MAX_COMBINATIONS = 384;

const permutations = (list: string[]): string[][] => {
  if (list.length <= 1) return [list.slice()];
  const result: string[][] = [];
  list.forEach((head, i) => {
    permutations([...list.slice(0, i), ...list.slice(i + 1)]).forEach((tail) => result.push([head, ...tail]));
  });
  return result;
};

const segmentsCross = (a: number, b: number, c: number, d: number) => (a - c) * (b - d) < 0;

const placeStraight = (
  layers: string[][],
  sep: (a: string, b: string) => number,
  straightLinks: StraightLink[],
  slack: number,
): Map<string, number> => {
  const spans = layers.map((layer) => layer.slice(1).reduce((sum, id, i) => sum + sep(layer[i], id), 0));
  const band = Math.max(0, ...spans) + slack;
  // Incoming segments of every node, from the rank above: [source, offset of the port across the flow].
  const incoming = new Map<string, [string, number][]>();
  straightLinks.forEach((l) => l.chain.slice(1).forEach((v, i) => {
    if (!incoming.has(v)) incoming.set(v, []);
    incoming.get(v)!.push([l.chain[i], i === 0 ? l.offset : 0]);
  }));
  // Pack wanted positions into the band, in the given order, as close to them as the gaps allow.
  const pack = (order: string[], wanted: number[]) => {
    const xs: number[] = [];
    order.forEach((id, i) => xs.push(i === 0 ? Math.max(0, wanted[0]) : Math.max(wanted[i], xs[i - 1] + sep(order[i - 1], id))));
    for (let i = order.length - 1; i >= 0; i -= 1) {
      xs[i] = Math.min(xs[i], i === order.length - 1 ? band : xs[i + 1] - sep(order[i], order[i + 1]));
    }
    return xs;
  };
  // Orders of a rank: the crossing-reduced one first, then the permutations of a small rank that keep
  // the port order of every parent (out left of unmodified / no-match).
  const ordersOf = (layer: string[]) => {
    if (layer.length > MAX_PERMUTED_RANK) return [layer];
    const keepsPorts = (order: string[]) => order.every((a, i) => order.slice(i + 1).every((b) => {
      const fromA = incoming.get(a) ?? [];
      const fromB = incoming.get(b) ?? [];
      return fromA.every(([ua, oa]) => fromB.every(([ub, ob]) => ua !== ub || oa <= ob));
    }));
    const key = layer.join('|');
    return [layer, ...permutations(layer).filter((o) => o.join('|') !== key && keepsPorts(o))];
  };
  interface Picture { score: number; elbows: number; x: Map<string, number> }
  const first = layers[0] ?? [];
  let beams: Picture[] = [...new Set([0, (band - spans[0]) / 2, band - spans[0]])].map((start) => {
    const xs = pack(first, first.map(() => start));
    return { score: 0, elbows: 0, x: new Map(first.map((id, i) => [id, xs[i]])) };
  });
  layers.slice(1).forEach((layer) => {
    const orders = ordersOf(layer);
    const next = new Map<string, Picture>();
    beams.forEach((picture) => {
      const target = (v: string) => (incoming.get(v) ?? []).map(([u, o]) => picture.x.get(u)! + o);
      // A small rank aims each node at any port of the rank (a node may make room for its neighbour's
      // straight link); a wide one at its own ports only. Both sides of the band are always tried.
      const shared = [...new Set(layer.flatMap(target))];
      const candidatesOf = (v: string) => {
        const own = target(v);
        const mean = own.length ? [own.reduce((s, t) => s + t, 0) / own.length] : [band / 2];
        const list = layer.length <= 3 ? [...shared, ...mean, 0, band] : [...own, ...mean];
        return [...new Set(list)].sort((a, b) => a - b);
      };
      const candidates = new Map(layer.map((v) => [v, candidatesOf(v)]));
      orders.forEach((order) => {
        // Every combination of candidates, bounded: past the bound, the later nodes keep their first ones.
        let combos: number[][] = [[]];
        order.forEach((v) => {
          const list = candidates.get(v)!;
          const room = Math.max(1, Math.floor(MAX_COMBINATIONS / combos.length));
          const kept = list.length <= room ? list : list.slice(0, room);
          combos = combos.flatMap((c) => kept.map((t) => [...c, t]));
        });
        combos.forEach((wanted) => {
          const xs = pack(order, wanted);
          let straight = 0;
          let elbows = 0;
          const segments: [number, number][] = [];
          order.forEach((v, i) => (incoming.get(v) ?? []).forEach(([u, o]) => {
            const from = picture.x.get(u)! + o;
            const gap = Math.abs(from - xs[i]);
            if (gap < 0.5) straight += 1;
            elbows += gap;
            segments.push([from, xs[i]]);
          }));
          let crossings = 0;
          for (let a = 0; a < segments.length; a += 1) {
            for (let b = a + 1; b < segments.length; b += 1) {
              if (segmentsCross(segments[a][0], segments[a][1], segments[b][0], segments[b][1])) crossings += 1;
            }
          }
          const score = picture.score + straight - CROSSING_PENALTY * crossings;
          const total = picture.elbows + elbows;
          const key = order.map((v, i) => `${v}@${Math.round(xs[i])}`).sort().join('|');
          const known = next.get(key);
          if (!known || score > known.score + 1e-9 || (Math.abs(score - known.score) < 1e-9 && total < known.elbows - 1e-6)) {
            const x = new Map(picture.x);
            order.forEach((v, i) => x.set(v, xs[i]));
            next.set(key, { score, elbows: total, x });
          }
        });
      });
    });
    // Stable sort: equal pictures keep the order they were generated in.
    beams = [...next.values()].sort((a, b) => b.score - a.score || a.elbows - b.elbows).slice(0, BEAM);
  });
  return beams[0].x;
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
  const sep = (a: string, b: string) => {
    const A = layered.get(a)!;
    const B = layered.get(b)!;
    return A.w / 2 + B.w / 2 + (A.dummy || B.dummy ? gapSibling * 0.4 : gapSibling);
  };
  const portCount = (id: string) => {
    const node = nodes.find((n) => n.id === id);
    const outs = ((node && components.get(node.component_id)?.ports) || []).filter((p) => p.type === 'out');
    return Math.max(outs.length, Math.max(1, ...links.filter((l) => l.from.id === id).map((l) => portIndex(components, node, l.from.port) + 1)));
  };
  const defaultPortOffset = (index: number, count: number) => (breadth / count) * (index + 0.5) - breadth / 2;
  const portOffset = options.portOffset ?? defaultPortOffset;
  const byNode = new Map(nodes.map((n) => [n.id, n]));
  const linkOffset = new Map(links.map((l) => [l.id, portOffset(portIndex(components, byNode.get(l.from.id), l.from.port), portCount(l.from.id))]));
  // Several ports of one step feeding the same child (out and unmodified both to the next step): the
  // child aims at the middle of those ports, so the pair is drawn symmetric and the chain stays on one line.
  const pairs = new Map<string, StraightLink & { offsets: number[] }>();
  links.filter((l) => chains.has(l.id)).forEach((l) => {
    const key = `${l.from.id}>${l.to.id}`;
    const found = pairs.get(key);
    if (found) found.offsets.push(linkOffset.get(l.id)!);
    else pairs.set(key, { id: l.id, chain: chains.get(l.id)!, offset: 0, offsets: [linkOffset.get(l.id)!] });
  });
  const straightLinks = [...pairs.values()].map(({ id, chain, offsets }) => ({ id, chain, offset: offsets.reduce((s, o) => s + o, 0) / offsets.length }));
  const x = placeStraight(ordering.layers, sep, straightLinks, breadth / 4);
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
