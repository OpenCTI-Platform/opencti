import { useCallback } from 'react';
import { Connection, useReactFlow, MarkerType, Edge, Node, addEdge } from 'reactflow';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../../../components/Theme';

export const useStatusConnection = () => {
  const theme = useTheme<Theme>();
  const { setNodes, setEdges, getNode } = useReactFlow();

  return useCallback((params: Connection) => {
    const sourceNode = getNode(params.source!);
    const targetNode = getNode(params.target!);

    if (!sourceNode || !targetNode) return;

    const sourceType = sourceNode.type;
    const targetType = targetNode.type;

    // Status -> Status (insert Transition)
    if (sourceType === 'status' && targetType === 'status') {
      const transitionId = `transition-${sourceNode.id}-${targetNode.id}-${Date.now()}`;

      const newTransitionNode: Node = {
        id: transitionId,
        type: 'transition',
        data: { event: 'NEW_EVENT', conditions: [] },
        position: { x: 0, y: 0 },
      };

      const newEdges: Edge[] = [
        {
          id: `e-${sourceNode.id}->${transitionId}`,
          source: sourceNode.id,
          target: transitionId,
          type: 'transition',
        },
        {
          id: `e-${transitionId}->${targetNode.id}`,
          source: transitionId,
          target: targetNode.id,
          type: 'transition',
          markerEnd: { type: MarkerType.ArrowClosed, color: theme.palette.chip?.main },
        },
      ];

      setNodes((nds) => [...nds, newTransitionNode]);
      setEdges((eds) => [...eds, ...newEdges]);
      return;
    }

    // Transition -> Transition (insert Status)
    if (sourceType === 'transition' && targetType === 'transition') {
      const statusId = `status-between-${Date.now()}`;

      const newStatusNode: Node = {
        id: statusId,
        type: 'status',
        data: { name: 'NEW_STATUS', color: '#ccc' },
        position: { x: 0, y: 0 },
      };

      const newEdges: Edge[] = [
        {
          id: `e-${sourceNode.id}->${statusId}`,
          source: sourceNode.id,
          target: statusId,
          type: 'transition',
          markerEnd: { type: MarkerType.ArrowClosed, color: theme.palette.chip?.main },
        },
        {
          id: `e-${statusId}->${targetNode.id}`,
          source: statusId,
          target: targetNode.id,
          type: 'transition',
        },
      ];

      setNodes((nds) => [...nds, newStatusNode]);
      setEdges((eds) => [...eds, ...newEdges]);
      return;
    }

    // Status -> Transition or Transition -> Status
    setEdges((eds) => addEdge({
      ...params,
      type: 'transition',
      ...(sourceType === 'transition' ? { markerEnd: { type: MarkerType.ArrowClosed, color: theme.palette.chip?.main } } : {}),
    }, eds));
  }, [getNode, setNodes, setEdges, theme]);
};
