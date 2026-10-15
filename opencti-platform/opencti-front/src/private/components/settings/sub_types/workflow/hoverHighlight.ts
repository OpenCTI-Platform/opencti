import { WorkflowNodeType } from './utils';
import type { LayoutInputEdge, LayoutInputNode } from './layout/types';

export interface HoverHighlight {
  nodeIds: Set<string>;
  edgeIds: Set<string>;
}

// What stays lit while a node is hovered; everything else is dimmed.
// - Status: its parent and child transitions, the statuses before and after them, and its own
//   placeholder, with the edges between them.
// - Transition (or placeholder): its source and target statuses, with their edges.
// Returns null when nothing is hovered or the id is no longer on the canvas.
export const getHoverHighlight = (hoveredId: string | null, nodes: LayoutInputNode[], edges: LayoutInputEdge[]): HoverHighlight | null => {
  const hovered = hoveredId ? nodes.find((n) => n.id === hoveredId) : undefined;
  if (!hovered) return null;
  const typeOf = new Map(nodes.map((n) => [n.id, n.type]));
  const nodeIds = new Set([hovered.id]);
  const edgeIds = new Set<string>();
  const light = (edge: LayoutInputEdge) => {
    edgeIds.add(edge.id);
    nodeIds.add(edge.source);
    nodeIds.add(edge.target);
  };
  const incoming = (id: string) => edges.filter((e) => e.target === id);
  const outgoing = (id: string) => edges.filter((e) => e.source === id);

  incoming(hovered.id).forEach((edge) => {
    light(edge);
    if (hovered.type === WorkflowNodeType.status && typeOf.get(edge.source) === WorkflowNodeType.transition) {
      incoming(edge.source).forEach(light);
    }
  });
  outgoing(hovered.id).forEach((edge) => {
    light(edge);
    if (hovered.type === WorkflowNodeType.status && typeOf.get(edge.target) === WorkflowNodeType.transition) {
      outgoing(edge.target).forEach(light);
    }
  });
  return { nodeIds, edgeIds };
};
