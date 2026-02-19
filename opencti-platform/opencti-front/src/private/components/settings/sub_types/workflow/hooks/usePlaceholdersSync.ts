import { useEffect } from 'react';
import { Node, Edge, MarkerType, useReactFlow } from 'reactflow';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../../../components/Theme';

// export const usePlaceholdersSync = (nodes, edges) => {
export const usePlaceholdersSync = (nodes: Node[], edges: Edge[]) => {
  const theme = useTheme<Theme>();
  const { setNodes, setEdges, getNode } = useReactFlow();

  useEffect(() => {
    // 1. Current status nodes
    const statusNodes = nodes.filter((n) => n.type === 'status');

    // 2. Find node statuses that need a placeholder
    const endStatuses = statusNodes.filter((node) =>
      !edges.some((edge) => edge.source === node.id && getNode(edge.target)?.type === 'transition'),
    );

    // 3. Map statuses to placeholder nodes
    const requiredPlaceholderNodes: Node[] = endStatuses.map((status) => ({
      id: `placeholder-${status.id}`,
      type: 'placeholder',
      data: {},
      position: { x: 0, y: 0 }, // Auto-layout will handle this later
    }));

    // 4. Map statuses to placeholder edges
    const requiredPlaceholderEdges: Edge[] = endStatuses.map((status) => ({
      id: `e-${status.id}->placeholder-${status.id}`,
      source: status.id,
      target: `placeholder-${status.id}`,
      markerEnd: { type: MarkerType.ArrowClosed, color: theme.palette.chip?.main },
      style: {
        strokeWidth: 0.5,
        strokeDasharray: '3 3',
        stroke: theme.palette.chip?.main,
      },
    }));

    // 5. Check if we actually need to update to avoid infinite loops
    const currentPlaceholderIds = nodes.filter((n) => n.type === 'placeholder').map((n) => n.id);
    const nextPlaceholderIds = requiredPlaceholderNodes.map((n) => n.id);
    const hasChanged = currentPlaceholderIds.length !== nextPlaceholderIds.length
      || !currentPlaceholderIds.every((id) => nextPlaceholderIds.includes(id));

    if (hasChanged) {
      // Remove old placeholders and add new ones
      setNodes((nds) => [
        ...nds.filter((n) => n.type !== 'placeholder'),
        ...requiredPlaceholderNodes,
      ]);
      setEdges((eds) => [
        ...eds.filter((e) => {
          const targetNode = getNode(e.target);
          return targetNode?.type !== 'placeholder';
        }),
        ...requiredPlaceholderEdges,
      ]);
    }
  }, [nodes.length, edges.length]);
};
