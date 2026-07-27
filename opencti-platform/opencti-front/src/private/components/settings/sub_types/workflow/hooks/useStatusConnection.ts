import { useCallback } from 'react';
import { Connection, useReactFlow, MarkerType, Edge, Node, addEdge } from 'reactflow';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../../../components/Theme';
import { NEW_EVENT_NAME, WorkflowNodeType } from '../utils';

export const useStatusConnection = () => {
  const theme = useTheme<Theme>();
  const { setNodes, setEdges, getNode, getEdges } = useReactFlow();

  return useCallback((params: Connection) => {
    const sourceNode = getNode(params.source!);
    const targetNode = getNode(params.target!);

    if (!sourceNode || !targetNode) return;

    const sourceType = sourceNode.type;
    const targetType = targetNode.type;
    const currentEdges = getEdges();

    // Guard Logic: Prevent multiple connections for Transition nodes
    // If source is a Transition, check if it already has an outgoing edge
    if (sourceType === WorkflowNodeType.transition) {
      const alreadyHasOutgoing = currentEdges.some((e) => e.source === params.source);
      if (alreadyHasOutgoing || targetType === WorkflowNodeType.transition) return;
    }

    // Status -> Status (insert Transition)
    if (sourceType === WorkflowNodeType.status && targetType === WorkflowNodeType.status) {
      const transitionId = `${WorkflowNodeType.transition}-${sourceNode.id}-${targetNode.id}-${Date.now()}`;

      const newTransitionNode: Node = {
        id: transitionId,
        type: WorkflowNodeType.transition,
        data: { event: NEW_EVENT_NAME, conditions: {} },
        position: { x: 0, y: 0 },
      };

      const newEdges: Edge[] = [
        {
          id: `e-${sourceNode.id}->${transitionId}`,
          source: sourceNode.id,
          target: transitionId,
          type: WorkflowNodeType.transition,
        },
        {
          id: `e-${transitionId}->${targetNode.id}`,
          source: transitionId,
          target: targetNode.id,
          type: WorkflowNodeType.transition,
          markerEnd: { type: MarkerType.ArrowClosed, color: theme.palette.chip?.main },
        },
      ];

      setNodes((nds) => [...nds, newTransitionNode]);
      setEdges((eds) => [...eds, ...newEdges]);
      return;
    }

    // Status -> Transition or Transition -> Status
    setEdges((eds) => addEdge({
      ...params,
      type: WorkflowNodeType.transition,
      ...(
        sourceType === WorkflowNodeType.transition
          ? { markerEnd: { type: MarkerType.ArrowClosed, color: theme.palette.chip?.main } }
          : {}
      ),
    }, eds));
  }, [getNode, getEdges, setNodes, setEdges, theme]);
};
