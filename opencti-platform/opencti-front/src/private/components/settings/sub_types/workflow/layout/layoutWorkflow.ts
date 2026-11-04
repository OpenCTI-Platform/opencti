import type { XYPosition } from 'reactflow';
import { buildGraph, rankGraph } from './rank';
import { orderLayers } from './order';
import { placeX } from './place';
import { placeLanes } from './lanes';
import { routeEdges } from './route';
import type { LayoutInputEdge, LayoutInputNode, LayoutNodeHints, LayoutOptions, LayoutResult } from './types';

// Layered layout for workflow graphs (status -> transition -> status). Pure and deterministic:
// same input, same output. Phases: break cycles and rank (rank.ts), reduce crossings (order.ts),
// place on x (place.ts), side lanes for loops (lanes.ts), orthogonal routing (route.ts).
export const layoutWorkflow = (nodes: LayoutInputNode[], edges: LayoutInputEdge[], { spacing, initialStatusId }: LayoutOptions): LayoutResult => {
  const result: LayoutResult = { positions: new Map(), nodeHints: new Map(), routes: new Map() };
  const graph = buildGraph(nodes, edges);
  if (graph.nodes.size === 0) return result;
  const [gapX, gapY] = spacing;
  const pitch = graph.maxHeight + gapY;

  const ranked = rankGraph(graph, initialStatusId);
  const ordering = orderLayers(graph, ranked);
  const x = placeX(ranked, ordering, gapX);
  const { place, items } = placeLanes(graph, ranked, x, gapX, pitch);
  result.routes = routeEdges({ graph, ranked, x, place, items, pitch });

  const laneOf = new Map(items.filter((i) => i.kind === 'node').map((i) => [i.id, i.side]));
  place.forEach((p, id) => {
    const position: XYPosition = { x: p.cx - p.w / 2, y: p.cy - p.h / 2 };
    const hints: LayoutNodeHints = { backward: laneOf.has(id), lane: laneOf.get(id) ?? null, rank: p.rank };
    result.positions.set(id, position);
    result.nodeHints.set(id, hints);
  });
  return result;
};
