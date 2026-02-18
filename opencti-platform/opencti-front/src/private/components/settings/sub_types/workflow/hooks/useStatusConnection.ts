import { useCallback } from 'react';
import { Connection, useReactFlow, MarkerType, Edge, Node } from 'reactflow';

export const useStatusConnection = () => {
  const { setNodes, setEdges, getNode } = useReactFlow();

  const onConnect = useCallback((params: Connection) => {
    const sourceNode = getNode(params.source!);
    const targetNode = getNode(params.target!);

    if (sourceNode?.type === 'status' && targetNode?.type === 'status') {
      const transitionId = `transition-${sourceNode.id}-${targetNode.id}`;

      // 1. Create the transition node
      const newTransitionNode: Node = {
        id: transitionId,
        type: 'transition',
        data: { event: 'NEW_EVENT', conditions: [] },
        position: { x: 0, y: 0 },
        // TODO fix position in layout
        // position: {
        //   x: (sourceNode.position.x + targetNode.position.x) / 2,
        //   y: (sourceNode.position.y + targetNode.position.y) / 2,
        // },
      };

      // 2. Create the two edges
      const newEdges: Edge[] = [
        {
          id: `e-${sourceNode.id}->${transitionId}`,
          source: sourceNode.id!,
          target: transitionId,
          type: 'transition',
        },
        {
          id: `e-${transitionId}->${targetNode.id}`,
          source: transitionId,
          target: targetNode.id!,
          type: 'transition',
          markerEnd: { type: MarkerType.ArrowClosed },
        },
      ];

      setNodes((nds) => [...nds, newTransitionNode]);
      setEdges((eds) => [...eds, ...newEdges]);
    }
  }, [getNode, setNodes, setEdges]);

  return onConnect;
};
