import { useMemo } from 'react';
import ReactFlow, { Background, BackgroundVariant, type Edge, MiniMap, type Node } from 'reactflow';
import 'reactflow/dist/style.css';
import type { NormalizedSchema } from '../../data/schemaTypes';
import { useSchemaGraphStore } from '../../state/schemaGraphStore';
import { typeTone } from '../../shared/theme/typeAppearance';
import type { GraphNode, RelationGraphEdge } from './buildVisibleGraph';
import { CanvasControls } from './CanvasControls';
import { CanvasEmptyState } from './CanvasEmptyState';
import { CanvasStatusBar } from './CanvasStatusBar';
import { EdgeMarkers } from './edges/EdgeMarkers';
import type { EdgeEmphasis, InheritanceEdgeData, RelationEdgeData } from './edges/edgeData';
import { edgeTypes } from './edges/edgeTypes';
import { relationEdgeId, typeIdOfNode, typeNodeId } from './graphIds';
import { useFitViewOnChange } from './hooks/useFitViewOnChange';
import { useDagreLayout } from './layout/useDagreLayout';
import type { TargetGroupNodeData, TypeNodeData } from './nodes/nodeData';
import { nodeTypes } from './nodes/nodeTypes';
import { useVisibleGraph } from './useGraphScope';
import './canvas.css';

const MAX_LABEL_NAMES = 2;

const labelOf = (schema: NormalizedSchema, nodeId: string) => {
  const typeId = typeIdOfNode(nodeId);
  return typeId ? schema.types.get(typeId)?.label ?? typeId : 'target group';
};

const describeEdge = (schema: NormalizedSchema, edge: RelationGraphEdge) => {
  const names = [...new Set(edge.relations.map((relation) => relation.name))];
  const label = names.length > MAX_LABEL_NAMES
    ? `${names.slice(0, MAX_LABEL_NAMES).join(', ')} +${names.length - MAX_LABEL_NAMES}`
    : names.join(', ');
  const description = edge.relations
    .map((relation) => (relation.viaTypeId ? `${relation.name} (via ${schema.types.get(relation.viaTypeId)?.label ?? relation.viaTypeId})` : relation.name))
    .join('\n');
  const tone: RelationEdgeData['tone'] = edge.relations.every((relation) => relation.kind === 'ref') ? 'ref' : 'relationship';
  return { label, description, tone };
};

/** React Flow wrapper: turns the derived graph and its layout into nodes and edges. No business rules here. */
export const SchemaCanvas = ({ schema }: { schema: NormalizedSchema }) => {
  const graph = useVisibleGraph(schema);
  const direction = useSchemaGraphStore((state) => state.direction);
  const includeRefs = useSchemaGraphStore((state) => state.includeRefs);
  const selectedTypeId = useSchemaGraphStore((state) => state.selectedTypeId);
  const hasPath = useSchemaGraphStore((state) => state.path !== null);
  const selectType = useSchemaGraphStore((state) => state.selectType);
  const toggleExpand = useSchemaGraphStore((state) => state.toggleExpand);
  const pinTypes = useSchemaGraphStore((state) => state.pinTypes);

  const layout = useDagreLayout(schema, graph, direction);
  useFitViewOnChange(graph, layout);

  const relationCounts = useMemo(() => {
    const counts = new Map<string, number>();
    for (const relation of schema.relations.values()) {
      if (relation.kind === 'ref' && !includeRefs) continue;
      counts.set(relation.sourceTypeId, (counts.get(relation.sourceTypeId) ?? 0) + 1);
      for (const target of relation.targetTypeIds) counts.set(target, (counts.get(target) ?? 0) + 1);
    }
    return counts;
  }, [schema, includeRefs]);

  const usageCounts = useMemo(() => {
    const counts = new Map<string, number>();
    for (const relation of schema.relations.values()) {
      if (relation.relationshipTypeId) counts.set(relation.relationshipTypeId, (counts.get(relation.relationshipTypeId) ?? 0) + relation.targetTypeIds.length);
    }
    return counts;
  }, [schema]);

  // Node data only changes with the graph, so selecting a node does not re-render the others.
  const nodeData = useMemo(() => new Map<string, TypeNodeData | TargetGroupNodeData>(graph.nodes.map((node: GraphNode) => {
    if (node.kind === 'group') {
      return [node.id, { group: node, direction, onReveal: pinTypes }];
    }
    const type = schema.types.get(node.typeId);
    if (!type) throw new Error(`Unknown type ${node.typeId}`);
    return [node.id, {
      type,
      role: node.role,
      direction,
      relationCount: relationCounts.get(type.id) ?? 0,
      usageCount: usageCounts.get(type.id) ?? 0,
      onToggleExpand: toggleExpand,
    }];
  })), [graph, schema, direction, relationCounts, usageCounts, pinTypes, toggleExpand]);

  const focus = useMemo(() => {
    if (hasPath || !selectedTypeId) return null;
    const selectedNode = typeNodeId(selectedTypeId);
    if (!layout.positions.has(selectedNode)) return null;
    const related = new Set([selectedNode]);
    for (const edge of graph.edges) {
      if (edge.source === selectedNode) related.add(edge.target);
      if (edge.target === selectedNode) related.add(edge.source);
    }
    return { selectedNode, related };
  }, [graph, layout, selectedTypeId, hasPath]);

  const nodes = useMemo<Node[]>(() => graph.nodes.map((node) => {
    const size = layout.sizes.get(node.id) ?? { width: 0, height: 0 };
    const data = nodeData.get(node.id);
    const type = node.kind === 'type' ? schema.types.get(node.typeId) : undefined;
    return {
      id: node.id,
      type: node.kind === 'group' ? 'targetGroup' : type?.kind === 'relationship' ? 'relationship' : 'entity',
      position: layout.positions.get(node.id) ?? { x: 0, y: 0 },
      data,
      width: size.width,
      height: size.height,
      style: { width: size.width, height: size.height },
      className: [focus && !focus.related.has(node.id) ? 'is-dimmed' : '', type ? `sv-tone-${typeTone(type)}` : 'sv-tone-group'].join(' '),
      selectable: false,
      draggable: false,
      connectable: false,
    };
  }), [graph, layout, nodeData, focus, schema]);

  const edges = useMemo<Edge[]>(() => {
    const edgeIds = new Set(graph.edges.map((edge) => edge.id));
    return graph.edges.map((edge) => {
      let emphasis: EdgeEmphasis = 'normal';
      if (hasPath) emphasis = 'highlighted';
      else if (focus) emphasis = edge.source === focus.selectedNode || edge.target === focus.selectedNode ? 'highlighted' : 'dimmed';
      if (edge.kind === 'inheritance') {
        return { id: edge.id, source: edge.source, target: edge.target, type: 'inheritance', ariaLabel: `${labelOf(schema, edge.target)} is a ${labelOf(schema, edge.source)}`, data: { indirect: edge.indirect, emphasis } satisfies InheritanceEdgeData, zIndex: 0 };
      }
      return {
        id: edge.id,
        source: edge.source,
        target: edge.target,
        type: 'relation',
        ariaLabel: `${labelOf(schema, edge.source)} ${[...new Set(edge.relations.map((relation) => relation.name))].join(', ')} ${labelOf(schema, edge.target)}`,
        data: {
          relations: edge.relations,
          emphasis,
          parallel: edge.source !== edge.target && edgeIds.has(relationEdgeId(edge.target, edge.source)),
          ...describeEdge(schema, edge),
        } satisfies RelationEdgeData,
        zIndex: emphasis === 'highlighted' ? 2 : 1,
      };
    });
  }, [graph, focus, hasPath, schema]);

  return (
    <div className="sv-canvas">
      <EdgeMarkers />
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        edgeTypes={edgeTypes}
        onNodeClick={(_, node) => node.type !== 'targetGroup' && selectType((node.data as TypeNodeData).type.id)}
        onNodeDoubleClick={(_, node) => {
          const data = node.data as TypeNodeData;
          if (node.type === 'entity' && data.relationCount > 0) toggleExpand(data.type.id);
        }}
        onPaneClick={() => selectType(null)}
        minZoom={0.05}
        maxZoom={2}
        nodesDraggable={false}
        nodesConnectable={false}
        elementsSelectable={false}
        onlyRenderVisibleElements
        proOptions={{ hideAttribution: true }}
      >
        <Background variant={BackgroundVariant.Dots} gap={22} size={1.2} />
        <MiniMap
          pannable
          zoomable
          nodeClassName={(node) => node.className?.split(' ').find((name) => name.startsWith('sv-tone-')) ?? ''}
          nodeBorderRadius={4}
          className="sv-minimap"
          ariaLabel="Canvas overview"
        />
        <CanvasControls />
        <CanvasStatusBar graph={graph} />
      </ReactFlow>
      {graph.nodes.length === 0 && <CanvasEmptyState />}
    </div>
  );
};
