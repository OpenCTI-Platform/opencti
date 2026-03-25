import { useEffect, useMemo } from 'react';
import { Node, Edge, MarkerType, useReactFlow } from 'reactflow';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../../../components/Theme';
import { WorkflowNodeType } from '../utils';

export const usePlaceholdersSync = (nodes: Node[], edges: Edge[]) => {
  const theme = useTheme<Theme>();
  const { setNodes, setEdges } = useReactFlow();

  // 1. Create a unique key
  // This effect will only re-run if a status or transition is added/removed.
  const structuralKey = useMemo(() => {
    const statusIds = nodes
      .flatMap((n) => (n.type === WorkflowNodeType.status ? [n.id] : []))
      .sort()
      .join(',');

    const edgeConnections = edges
      .flatMap((e) => (!e.id.includes(WorkflowNodeType.placeholder) ? [`${e.source}->${e.target}`] : []))
      .sort()
      .join(',');

    return `${statusIds}|${edgeConnections}`;
  }, [nodes, edges]);

  useEffect(() => {
    // 2. Filter for nodes only (ignore existing placeholders)
    const statusNodes = nodes.filter((n) => n.type === WorkflowNodeType.status);
    const transitionNodes = nodes.filter((n) => n.type === WorkflowNodeType.transition);
    const transitionNodeIds = new Set(transitionNodes.map((n) => n.id));

    // 3. Find node statuses that need a placeholder
    const endStatuses = statusNodes.filter((node) =>
      !edges.some((edge) =>
        edge.source === node.id && transitionNodeIds.has(edge.target),
      ),
    );

    const requiredPlaceholderNodes: Node[] = endStatuses.map((status) => ({
      id: `${WorkflowNodeType.placeholder}-${status.id}`,
      type: WorkflowNodeType.placeholder,
      data: {},
      position: { x: 0, y: 0 },
    }));

    const requiredPlaceholderEdges: Edge[] = endStatuses.map((status) => ({
      id: `e-${status.id}->${WorkflowNodeType.placeholder}-${status.id}`,
      source: status.id,
      target: `${WorkflowNodeType.placeholder}-${status.id}`,
      type: WorkflowNodeType.placeholder,
      markerEnd: { type: MarkerType.ArrowClosed, color: theme.palette.chip?.main },
      style: {
        strokeWidth: 0.5,
        strokeDasharray: '3 3',
        stroke: theme.palette.chip?.main,
      },
    }));

    // 4. Check if we actually need to update to avoid infinite loops
    const currentPlaceholderIds = nodes
      .flatMap((n) => (n.type === WorkflowNodeType.placeholder ? [n.id] : []))
      .sort();

    const nextPlaceholderIds = requiredPlaceholderNodes.map((n) => n.id).sort();

    const hasChanged = currentPlaceholderIds.length !== nextPlaceholderIds.length
      || !currentPlaceholderIds.every((id, index) => id === nextPlaceholderIds[index]);

    if (hasChanged) {
      // Remove old placeholders and add new ones
      setNodes((nds) => [
        ...nds.filter((n) => n.type !== WorkflowNodeType.placeholder),
        ...requiredPlaceholderNodes,
      ]);

      setEdges((eds) => [
        ...eds.filter((e) => (
          !e.id.includes(WorkflowNodeType.placeholder) && e.type !== WorkflowNodeType.placeholder
        )),
        ...requiredPlaceholderEdges,
      ]);
    }
  }, [structuralKey, theme]);
};
