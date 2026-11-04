import type { Edge, Node } from 'reactflow';
import { WorkflowNodeType } from './utils';

// Removes one connection from the workflow graph.
// - transition -> status: the transition stays, with no target (an unlinked transition).
// - status -> transition: that status stops being a source of the transition. When it was the
//   last source, the transition goes too, with its edges, so nothing is left unreachable.
export const deleteConnection = (nodes: Node[], edges: Edge[], edgeId: string): { nodes: Node[]; edges: Edge[] } => {
  const edge = edges.find((e) => e.id === edgeId);
  if (!edge) return { nodes, edges };
  const remaining = edges.filter((e) => e.id !== edgeId);
  const target = nodes.find((n) => n.id === edge.target);
  if (target?.type === WorkflowNodeType.transition && !remaining.some((e) => e.target === target.id)) {
    return {
      nodes: nodes.filter((n) => n.id !== target.id),
      edges: remaining.filter((e) => e.source !== target.id && e.target !== target.id),
    };
  }
  return { nodes, edges: remaining };
};
