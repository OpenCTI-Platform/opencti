import type { XYPosition } from 'reactflow';
import { WorkflowNodeType } from '../utils';
import type { Graph, LaneItem, Placement, RankedGraph } from './types';

const GUIDE = 14; // stub out of a side port before turning into a channel
const TRACK_MARGIN = 8; // bars closer than this cannot share a track
const EPSILON = 0.01;

// A horizontal segment whose y is decided later, by track assignment in channel `k`
// (the gap between row k and row k + 1).
interface ChannelRef {
  k: number;
  y: number;
  entry: ChannelSegment;
}
interface ChannelSegment {
  key: string;
  x1: number;
  x2: number;
  ref: ChannelRef;
  pins: { x: number; top: boolean }[];
}
interface RawPoint {
  x: number;
  y: number | ChannelRef;
}

export interface RouteContext {
  graph: Graph;
  ranked: RankedGraph;
  x: Map<string, number>;
  place: Map<string, Placement>;
  items: LaneItem[];
  pitch: number;
}

const simplify = (points: XYPosition[]): XYPosition[] => {
  const out: XYPosition[] = [];
  points.forEach((p) => {
    const last = out[out.length - 1];
    if (last && Math.abs(last.x - p.x) < EPSILON && Math.abs(last.y - p.y) < EPSILON) return;
    if (out.length >= 2) {
      const a = out[out.length - 2];
      const sameX = Math.abs(a.x - last.x) < EPSILON && Math.abs(last.x - p.x) < EPSILON;
      const sameY = Math.abs(a.y - last.y) < EPSILON && Math.abs(last.y - p.y) < EPSILON;
      if (sameX || sameY) out.pop();
    }
    out.push(p);
  });
  return out;
};

// Track assignment for one channel. Segments sharing a key (fan-out bar of a status, fan-in
// bar of a merge) share a track. Vertical constraints order the others: when a top pin of A
// lies inside B's span, A runs above B (else B's bar would cut A's vertical); a bottom pin
// means the reverse.
const assignTracks = (segments: ChannelSegment[], top: number, bottom: number) => {
  const groups = new Map<string, { x1: number; x2: number; refs: ChannelRef[]; pins: ChannelSegment['pins']; track: number }>();
  segments.forEach((s) => {
    const g = groups.get(s.key) ?? { x1: Infinity, x2: -Infinity, refs: [], pins: [], track: -1 };
    g.x1 = Math.min(g.x1, s.x1);
    g.x2 = Math.max(g.x2, s.x2);
    g.refs.push(s.ref);
    g.pins.push(...s.pins);
    groups.set(s.key, g);
  });
  const arr = [...groups.values()].sort((a, b) => a.x1 - b.x1 || a.x2 - b.x2);
  const overlap = (a: typeof arr[number], b: typeof arr[number]) => a.x1 < b.x2 + TRACK_MARGIN && b.x1 < a.x2 + TRACK_MARGIN;
  const inside = (px: number, g: typeof arr[number]) => px > g.x1 + 0.5 && px < g.x2 - 0.5;
  const below = arr.map(() => new Set<number>()); // below[i]: groups that must run under i
  const indegree = arr.map(() => 0);
  arr.forEach((a, i) => arr.forEach((b, j) => {
    if (i === j || !overlap(a, b)) return;
    a.pins.forEach((p) => {
      if (!inside(p.x, b)) return;
      const [upper, lower] = p.top ? [i, j] : [j, i];
      if (!below[upper].has(lower)) {
        below[upper].add(lower);
        indegree[lower] += 1;
      }
    });
  }));
  const done = arr.map(() => false);
  const order: number[] = [];
  while (order.length < arr.length) {
    // Kahn's order; on a cycle, release the leftmost waiting group (one unavoidable crossing).
    let next = arr.findIndex((_, i) => !done[i] && indegree[i] === 0);
    if (next < 0) next = arr.findIndex((_, i) => !done[i]);
    done[next] = true;
    order.push(next);
    below[next].forEach((j) => {
      indegree[j] -= 1;
    });
  }
  const minTrack = arr.map(() => 0);
  let tracks = 0;
  order.forEach((i) => {
    const g = arr[i];
    let t = minTrack[i];
    while (arr.some((o, j) => j !== i && o.track === t && overlap(o, g))) t += 1;
    g.track = t;
    tracks = Math.max(tracks, t + 1);
    below[i].forEach((j) => {
      minTrack[j] = Math.max(minTrack[j], t + 1);
    });
  });
  arr.forEach((g) => {
    const y = top + ((g.track + 1) * (bottom - top)) / (tracks + 1);
    g.refs.forEach((r) => {
      r.y = y;
    });
  });
};

// Phase 7: orthogonal routes for every edge.
export const routeEdges = ({ graph, ranked, x, place, items, pitch }: RouteContext): Map<string, XYPosition[]> => {
  const { forwardEdges, chains, fOut, fIn, layered } = ranked;
  const rowY = (r: number) => r * pitch;
  const channels = new Map<number, ChannelSegment[]>();
  const channel = (k: number, key: string, xa: number, xb: number): ChannelRef => {
    const ref = { k, y: 0 } as ChannelRef;
    ref.entry = { key, x1: Math.min(xa, xb), x2: Math.max(xa, xb), ref, pins: [] };
    if (!channels.has(k)) channels.set(k, []);
    channels.get(k)!.push(ref.entry);
    return ref;
  };
  const P = (id: string) => place.get(id)!;
  const boxes = [...place.entries()];
  const isClear = (y: number, xa: number, xb: number, ignore: string[]) => !boxes.some(([id, b]) => !ignore.includes(id)
    && Math.abs(y - b.cy) < b.h / 2 + 1
    && Math.min(xa, xb) < b.cx + b.w / 2 && Math.max(xa, xb) > b.cx - b.w / 2);
  // A status takes side ports at its quarters; a transition hexagon only touches its box sides
  // at its tips, at mid-height (see NodeTypes/TransitionNode.tsx).
  const port = (id: string, sign: number, dy: number): XYPosition => ({
    x: P(id).cx + sign * (P(id).w / 2),
    y: P(id).cy + (graph.nodes.get(id)!.type === WorkflowNodeType.transition ? 0 : dy),
  });
  // Leave a status by its side (lower quarter) towards lane x `lx`.
  const exitTo = (id: string, lx: number, sign: number, key: string, ignore: string[]): RawPoint[] => {
    const p = port(id, sign, P(id).h / 4);
    if (isClear(p.y, p.x, lx, [id, ...ignore])) return [p, { x: lx, y: p.y }];
    const gx = p.x + sign * GUIDE;
    const ref = channel(P(id).rank, key, gx, lx);
    return [p, { x: gx, y: p.y }, { x: gx, y: ref }, { x: lx, y: ref }];
  };
  // Enter a status by its side (upper quarter) from lane x `lx`.
  const enterFrom = (id: string, lx: number, sign: number, key: string, ignore: string[]): RawPoint[] => {
    const p = port(id, sign, -P(id).h / 4);
    if (isClear(p.y, p.x, lx, [id, ...ignore])) return [{ x: lx, y: p.y }, p];
    const gx = p.x + sign * GUIDE;
    const ref = channel(P(id).rank - 1, key, lx, gx);
    return [{ x: lx, y: ref }, { x: gx, y: ref }, { x: gx, y: p.y }, p];
  };

  const raw = new Map<string, RawPoint[]>();
  forwardEdges.forEach((e) => {
    const chain = chains.get(e.id)!;
    const s = chain[0];
    const t = chain[chain.length - 1];
    const points: RawPoint[] = [{ x: x.get(s)!, y: P(s).cy + P(s).h / 2 }];
    for (let i = 0; i + 1 < chain.length; i += 1) {
      const a = chain[i];
      const b = chain[i + 1];
      if (Math.abs(x.get(a)! - x.get(b)!) > 0.5) {
        let key = `e:${e.id}`;
        if (i === 0 && fOut.get(s)!.length > 1) key = `src:${s}`;
        else if (i === chain.length - 2 && fIn.get(t)!.length > 1) key = `tgt:${t}`;
        const ref = channel(layered.get(a)!.rank, key, x.get(a)!, x.get(b)!);
        points.push({ x: x.get(a)!, y: ref }, { x: x.get(b)!, y: ref });
      }
    }
    points.push({ x: x.get(t)!, y: P(t).cy - P(t).h / 2 });
    raw.set(e.id, points);
  });

  items.forEach((item) => {
    const { sign, lx } = item;
    if (item.kind === 'edge') {
      const { edge } = item;
      const target = P(edge.target);
      const ref = channel(target.rank - 1, `e:${edge.id}`, lx, target.cx);
      raw.set(edge.id, [
        ...exitTo(edge.source, lx, sign, `e:${edge.id}`, []),
        { x: lx, y: ref },
        { x: target.cx, y: ref },
        { x: target.cx, y: target.cy - target.h / 2 },
      ]);
      return;
    }
    const t = P(item.id);
    item.ins.forEach((e) => {
      const source = e.source;
      const key = `e:${e.id}`;
      if (item.selfLoop) {
        // Straight from the status side to the hexagon tip beside it, both at mid-height.
        const start = port(source, sign, 0);
        const tip = { x: t.cx - sign * (t.w / 2), y: t.cy };
        if (isClear(t.cy, start.x, tip.x, [source, item.id])) {
          raw.set(e.id, [start, tip]);
        } else {
          const p = port(source, sign, P(source).h / 4);
          const gx = p.x + sign * GUIDE;
          const ref = channel(P(source).rank, key, gx, t.cx);
          raw.set(e.id, [p, { x: gx, y: p.y }, { x: gx, y: ref }, { x: t.cx, y: ref }, { x: t.cx, y: t.cy + t.h / 2 }]);
        }
      } else if (P(source).rank > item.row) {
        raw.set(e.id, [...exitTo(source, lx, sign, key, [item.id]), { x: lx, y: t.cy + t.h / 2 }]);
      } else {
        // Rare: a source above the lane node (multi-source backward transition). Enter it from its outer side.
        const gx = lx + sign * (t.w / 2 + GUIDE);
        raw.set(e.id, [...exitTo(source, gx, sign, key, [item.id]), { x: gx, y: t.cy }, { x: lx + sign * (t.w / 2), y: t.cy }]);
      }
    });
    item.outs.forEach((out) => {
      const outKey = `e:${out.id}`;
      if (item.selfLoop && out.target === item.to) {
        const p = port(out.target, sign, -P(out.target).h / 4);
        const gx = p.x + sign * GUIDE;
        const ref = channel(P(out.target).rank - 1, outKey, t.cx, gx);
        raw.set(out.id, [{ x: t.cx, y: t.cy - t.h / 2 }, { x: t.cx, y: ref }, { x: gx, y: ref }, { x: gx, y: p.y }, p]);
      } else {
        raw.set(out.id, [{ x: lx, y: t.cy - t.h / 2 }, ...enterFrom(out.target, lx, sign, outKey, [item.id])]);
      }
    });
  });

  // Pins: a vertical neighbour coming from above the channel is a top pin, else a bottom pin.
  const level = (p: RawPoint) => (typeof p.y === 'number' ? p.y : rowY(p.y.k) + pitch / 2);
  raw.forEach((points) => {
    for (let i = 0; i + 1 < points.length; i += 1) {
      const ref = points[i].y;
      if (typeof ref !== 'number' && points[i + 1].y === ref) {
        const middle = rowY(ref.k) + pitch / 2;
        if (points[i - 1]) ref.entry.pins.push({ x: points[i].x, top: level(points[i - 1]) < middle });
        if (points[i + 2]) ref.entry.pins.push({ x: points[i + 1].x, top: level(points[i + 2]) < middle });
      }
    }
  });
  channels.forEach((segments, k) => assignTracks(segments, rowY(k) + graph.maxHeight / 2, rowY(k + 1) - graph.maxHeight / 2));

  const routes = new Map<string, XYPosition[]>();
  raw.forEach((points, id) => {
    routes.set(id, simplify(points.map((p) => ({ x: p.x, y: typeof p.y === 'number' ? p.y : p.y.y }))));
  });
  return routes;
};

// SVG path through the route with rounded corners, plus the middle of its longest segment
// (where TransitionEdge draws its hover badge).
export const getRoutePath = (points: XYPosition[], radius = 8): [string, number, number] => {
  let d = `M${points[0].x},${points[0].y}`;
  for (let i = 1; i < points.length - 1; i += 1) {
    const [p, c, n] = [points[i - 1], points[i], points[i + 1]];
    const r = Math.min(radius, Math.hypot(c.x - p.x, c.y - p.y) / 2, Math.hypot(n.x - c.x, n.y - c.y) / 2);
    const a = { x: c.x - Math.sign(c.x - p.x) * r, y: c.y - Math.sign(c.y - p.y) * r };
    const b = { x: c.x + Math.sign(n.x - c.x) * r, y: c.y + Math.sign(n.y - c.y) * r };
    d += ` L${a.x},${a.y} Q${c.x},${c.y} ${b.x},${b.y}`;
  }
  const last = points[points.length - 1];
  d += ` L${last.x},${last.y}`;
  let longest = 0;
  let middle: XYPosition = points[0];
  for (let i = 1; i < points.length; i += 1) {
    const length = Math.hypot(points[i].x - points[i - 1].x, points[i].y - points[i - 1].y);
    if (length > longest) {
      longest = length;
      middle = { x: (points[i].x + points[i - 1].x) / 2, y: (points[i].y + points[i - 1].y) / 2 };
    }
  }
  return [d, middle.x, middle.y];
};
