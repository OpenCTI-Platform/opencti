import { MarkerType, useReactFlow } from 'reactflow';
import type { Node, Edge } from 'reactflow';
import type { Status } from '../utils';

const useAddStatus = (selectedElement?: Edge | null) => {
  const { setNodes, setEdges, getNode } = useReactFlow();
  const onClick = (values: Status): void => {
    const sourceNode = selectedElement?.source ? getNode(selectedElement.source) : null;
    const targetNode = selectedElement?.target ? getNode(selectedElement.target) : null;

    const statusId = values.statusTemplate.id;

    console.log({ selectedElement, values });
    // 1. Add new from button (unlinked status)
    if (!sourceNode && !targetNode) {
      const newStatusNode: Node = {
        id: statusId,
        type: 'status',
        data: values,
        position: { x: 0, y: 0 },
      };
      setNodes((nds) => [...nds, newStatusNode]);
      return;
    }

    // 2. Add from a placeholder (append to end)
    if (sourceNode && !targetNode) {
      const transitionId = `transition-${sourceNode.id}-${statusId}`;

      const newTransNode: Node = {
        id: transitionId,
        type: 'transition',
        data: { event: 'NEW_EVENT', conditions: [] },
        position: sourceNode.position,
      };

      const newStatusNode: Node = {
        id: statusId,
        type: 'status',
        data: values,
        position: sourceNode.position,
      };

      const newEdges: Edge[] = [
        {
          id: `e-${sourceNode.id}->${transitionId}`,
          source: sourceNode.id,
          target: transitionId,
          type: 'transition',
        },
        {
          id: `e-${transitionId}->${statusId}`,
          source: transitionId,
          target: statusId,
          type: 'transition',
          markerEnd: { type: MarkerType.ArrowClosed },
        },
      ];

      setNodes((nds) => [...nds, newTransNode, newStatusNode]);
      setEdges((eds) => [...eds, ...newEdges]);
      return;
    }

    // 3. Add from edge (insert in between)
    if (sourceNode && targetNode) {
      let firstNewNode: Node;
      let secondNewNode: Node;

      if (sourceNode?.type === 'status') {
        const transitionId = `transition-${sourceNode.id}-${statusId}`;
        firstNewNode = {
          id: transitionId,
          type: 'transition',
          data: { event: 'NEW_EVENT', conditions: [] },
          position: sourceNode.position,
        };
        secondNewNode = {
          id: statusId,
          type: 'status',
          data: values,
          position: targetNode.position,
        };
      } else {
        const transitionId = `transition-${statusId}-${targetNode.id}`;
        firstNewNode = {
          id: statusId,
          type: 'status',
          data: values,
          position: sourceNode.position,
        };
        secondNewNode = {
          id: transitionId,
          type: 'transition',
          data: { event: 'NEW_EVENT', conditions: [] },
          position: targetNode.position,
        };
      }

      const newEdges: Edge[] = [
        {
          id: `e-${sourceNode.id}->${firstNewNode.id}`,
          source: sourceNode.id,
          target: firstNewNode.id,
          type: 'transition',
          ...(sourceNode.type === 'transition' ? { markerEnd: { type: MarkerType.ArrowClosed } } : {}),
        },
        {
          id: `e-${firstNewNode.id}->${secondNewNode.id}`,
          source: firstNewNode.id,
          target: secondNewNode.id,
          type: 'transition',
          ...(sourceNode.type === 'status' ? { markerEnd: { type: MarkerType.ArrowClosed } } : {}),
        },
        {
          id: `e-${secondNewNode.id}->${targetNode.id}`,
          source: secondNewNode.id,
          target: targetNode.id,
          type: 'transition',
          ...(sourceNode.type === 'transition' ? { markerEnd: { type: MarkerType.ArrowClosed } } : {}),
        },
      ];

      setNodes((nds) => [...nds, firstNewNode, secondNewNode]);
      setEdges((eds) => {
        const filteredEdges = eds.filter((edge) => edge.id !== selectedElement?.id);
        return [...filteredEdges, ...newEdges];
      });
    }
  };

  return onClick;
};

export default useAddStatus;
