import type { EdgeLaneItem, Graph, LaneItem, LaneSide, NodeLaneItem, Placement, RankedGraph } from './types';

const EDGE_LANE_GAP = 24; // distance from the graph (or the previous lane) to an edge-only lane

type PendingItem = Omit<NodeLaneItem, 'side' | 'sign' | 'lx'> | Omit<EdgeLaneItem, 'side' | 'sign' | 'lx'>;

export interface LaneLayout {
  place: Map<string, Placement>; // centre and size of every real node, lane nodes included
  items: LaneItem[];
}

// Phases 5 and 6: rows, then side lanes for backward transitions and back edges.
export const placeLanes = (graph: Graph, ranked: RankedGraph, x: Map<string, number>, gapX: number, pitch: number): LaneLayout => {
  const { rank, layered, backEdges, backwardTransitions } = ranked;
  const rowY = (r: number) => r * pitch;
  const place = new Map<string, Placement>();
  layered.forEach((n) => {
    if (!n.dummy) place.set(n.id, { cx: x.get(n.id)!, cy: rowY(n.rank), w: n.w, h: n.h, rank: n.rank });
  });
  const rowMin = new Map<number, number>();
  const rowMax = new Map<number, number>();
  layered.forEach((n) => {
    const cx = x.get(n.id)!;
    rowMin.set(n.rank, Math.min(rowMin.get(n.rank) ?? Infinity, cx - n.w / 2));
    rowMax.set(n.rank, Math.max(rowMax.get(n.rank) ?? -Infinity, cx + n.w / 2));
  });

  const pending: PendingItem[] = [];
  backwardTransitions.forEach((id) => {
    const ins = graph.inE.get(id)!.filter((e) => place.has(e.source));
    const outs = graph.outE.get(id)!;
    const to = outs[0].target;
    const targetRanks = outs.map((e) => rank.get(e.target)!);
    const sourceRanks = ins.map((e) => rank.get(e.source)!);
    const selfLoop = ins.length > 0 && ins.every((e) => e.source === to);
    // Sit one row above the source it leaves from, like a forward transition, and below every
    // target; a self-loop sits beside its status.
    // Without a placed source (not reachable from the editor), sit just below the targets: an
    // empty Math.min would make the lane span infinite.
    const belowTargets = Math.max(...targetRanks) + 1;
    let row = sourceRanks.length ? Math.max(Math.min(...sourceRanks) - 1, belowTargets) : belowTargets;
    if (selfLoop) row = rank.get(to)!;
    const all = [...targetRanks, row, ...sourceRanks];
    pending.push({ kind: 'node', id, ins, outs, to, row, selfLoop, r0: Math.min(...all), r1: Math.max(...all), order: graph.nodes.get(id)!.order });
  });
  graph.edges.filter((e) => backEdges.has(e.id) && !backwardTransitions.has(e.source)).forEach((edge) => {
    pending.push({ kind: 'edge', id: edge.id, edge, r0: rank.get(edge.target)! - 1, r1: rank.get(edge.source)!, order: graph.nodes.size + edge.order });
  });
  // Shortest span first: short loops take the inner lanes, long loops wrap around them.
  pending.sort((a, b) => (a.r1 - a.r0) - (b.r1 - b.r0) || a.order - b.order);

  const lanes: Record<LaneSide, { r0: number; r1: number; outer: number }[]> = { right: [], left: [] };
  const items = pending.map((item): LaneItem => {
    const isNode = item.kind === 'node';
    const w = isNode ? graph.nodes.get(item.id)!.w : 0;
    const ends = isNode ? [...item.outs.map((e) => e.target), ...item.ins.map((e) => e.source)] : [item.edge.source, item.edge.target];
    const candidates = (['right', 'left'] as LaneSide[]).map((side) => {
      const sign: 1 | -1 = side === 'right' ? 1 : -1;
      let extent = sign > 0 ? -Infinity : Infinity;
      const push = (v: number) => {
        extent = sign > 0 ? Math.max(extent, v) : Math.min(extent, v);
      };
      for (let r = item.r0; r <= item.r1; r += 1) {
        if (rowMax.has(r)) push(sign > 0 ? rowMax.get(r)! : rowMin.get(r)!);
      }
      lanes[side].filter((l) => l.r0 <= item.r1 && l.r1 >= item.r0).forEach((l) => push(l.outer));
      const center = extent + sign * (isNode ? gapX + w / 2 : EDGE_LANE_GAP);
      const cost = ends.reduce((s, id) => s + Math.abs(center - place.get(id)!.cx), 0);
      return { side, sign, center, cost };
    });
    const pick = candidates[0].cost <= candidates[1].cost ? candidates[0] : candidates[1];
    lanes[pick.side].push({ r0: item.r0, r1: item.r1, outer: pick.center + pick.sign * (w / 2) });
    if (item.kind === 'node') {
      const n = graph.nodes.get(item.id)!;
      place.set(item.id, { cx: pick.center, cy: rowY(item.row), w: n.w, h: n.h, rank: item.row });
    }
    return { ...item, side: pick.side, sign: pick.sign, lx: pick.center } as LaneItem;
  });
  return { place, items };
};
