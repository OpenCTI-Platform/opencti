import dagre from 'dagre';
import type { LayoutEngine, Position } from './LayoutEngine';

export const dagreLayoutEngine: LayoutEngine = {
  layout: (nodes, edges, direction) => {
    const graph = new dagre.graphlib.Graph({ multigraph: false });
    graph.setDefaultEdgeLabel(() => ({}));
    graph.setGraph({ rankdir: direction, ranksep: direction === 'TB' ? 90 : 140, nodesep: 36, edgesep: 16, marginx: 20, marginy: 20 });
    for (const node of nodes) graph.setNode(node.id, { width: node.width, height: node.height });
    for (const edge of edges) {
      if (edge.source !== edge.target) graph.setEdge(edge.source, edge.target, { weight: edge.weight });
    }
    dagre.layout(graph);

    const positions = new Map<string, Position>();
    for (const node of nodes) {
      const { x, y } = graph.node(node.id);
      positions.set(node.id, { x: x - node.width / 2, y: y - node.height / 2 });
    }
    return positions;
  },
};
