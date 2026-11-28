import { useMemo } from 'react';
import type { NormalizedSchema } from '../../../data/schemaTypes';
import type { VisibleGraph } from '../buildVisibleGraph';
import { nodeSize } from '../nodes/nodeSizes';
import { dagreLayoutEngine } from './dagreLayoutEngine';
import { withPackedLeaves } from './packLeaves';
import type { LayoutDirection, LayoutEngine, LayoutNode, Position } from './LayoutEngine';

export interface GraphLayout {
  positions: ReadonlyMap<string, Position>;
  sizes: ReadonlyMap<string, { width: number; height: number }>;
}

const INHERITANCE_WEIGHT = 3;
const STRUCTURAL_WEIGHT = 2;
const CONTEXT_WEIGHT = 1;

/**
 * Edges that place nodes. Relations that only connect types already placed by an expansion, a path
 * or the hierarchy are drawn but left out, otherwise expanding one type tangles every rank.
 */
const layoutEdges = (graph: VisibleGraph) => {
  const anchored = new Set<string>();
  for (const edge of graph.edges) {
    if (edge.kind === 'inheritance' || edge.structural) {
      anchored.add(edge.source);
      anchored.add(edge.target);
    }
  }
  return graph.edges
    .filter((edge) => edge.kind === 'inheritance' || edge.structural || !anchored.has(edge.source) || !anchored.has(edge.target))
    .map((edge) => ({
      source: edge.source,
      target: edge.target,
      weight: edge.kind === 'inheritance' ? INHERITANCE_WEIGHT : edge.structural ? STRUCTURAL_WEIGHT : CONTEXT_WEIGHT,
    }));
};

/** Re-layouts only when the set of visible node and edge ids changes, not on selection or hover. */
export const useDagreLayout = (
  schema: NormalizedSchema,
  graph: VisibleGraph,
  direction: LayoutDirection,
  engine: LayoutEngine = dagreLayoutEngine,
): GraphLayout => {
  const structureKey = useMemo(
    () => [
      ...graph.nodes.map((node) => (node.kind === 'group' ? `${node.id}#${node.typeIds.length}` : node.id)),
      '|',
      ...graph.edges.map((edge) => (edge.kind === 'relation' && edge.structural ? `${edge.id}*` : edge.id)),
    ].join('\n'),
    [graph],
  );

  return useMemo(() => {
    const isRelationshipType = (typeId: string) => schema.types.get(typeId)?.kind === 'relationship';
    const layoutNodes: LayoutNode[] = graph.nodes.map((node) => ({ id: node.id, ...nodeSize(node, isRelationshipType) }));
    const groupIds = new Set(graph.nodes.filter((node) => node.kind === 'group').map((node) => node.id));
    const packed = withPackedLeaves(engine, (id) => !groupIds.has(id));
    return {
      positions: packed.layout(layoutNodes, layoutEdges(graph), direction),
      sizes: new Map(layoutNodes.map((node) => [node.id, { width: node.width, height: node.height }])),
    };
    // graph is read through structureKey: a new graph object with the same ids keeps the layout.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [schema, structureKey, direction, engine]);
};
