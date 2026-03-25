import { MarkerType, isEdge, useReactFlow } from 'reactflow';
import type { Node, Edge } from 'reactflow';
import { NEW_EVENT_NAME, WorkflowNodeType, type Status } from '../utils';

const useAddStatus = (selectedElement: Node | Edge) => {
  const { setNodes, setEdges, getNode } = useReactFlow();
  const onClick = (values: Status): void => {
    const isPlaceholder = selectedElement?.type === WorkflowNodeType.placeholder;
    const sourceNode = (isEdge(selectedElement) || isPlaceholder) && (selectedElement as Edge)?.source ? getNode((selectedElement as Edge).source) : null;
    const targetNode = isEdge(selectedElement) && selectedElement?.target ? getNode(selectedElement.target) : null;

    const statusId = values.statusTemplate.id;

    // 1. Add new from button (unlinked status)
    if (!sourceNode && !targetNode) {
      const newStatusNode: Node = {
        id: statusId,
        type: WorkflowNodeType.status,
        data: values,
        position: { x: 0, y: 0 },
      };
      setNodes((nds) => [...nds, newStatusNode]);
      return;
    }

    // 2. Add from a placeholder (append to end)
    if (sourceNode && !targetNode) {
      const transitionId = `${WorkflowNodeType.transition}-${sourceNode.id}-${statusId}`;

      const newTransitionNode: Node = {
        id: transitionId,
        type: WorkflowNodeType.transition,
        data: { event: NEW_EVENT_NAME, conditions: [] },
        position: sourceNode.position,
      };

      const newStatusNode: Node = {
        id: statusId,
        type: WorkflowNodeType.status,
        data: values,
        position: sourceNode.position,
      };

      const newEdges: Edge[] = [
        {
          id: `e-${sourceNode.id}->${transitionId}`,
          source: sourceNode.id,
          target: transitionId,
          type: WorkflowNodeType.transition,
        },
        {
          id: `e-${transitionId}->${statusId}`,
          source: transitionId,
          target: statusId,
          type: WorkflowNodeType.transition,
          markerEnd: { type: MarkerType.ArrowClosed },
        },
      ];

      setNodes((nds) => [...nds.filter((n) => n.id !== selectedElement.id), newTransitionNode, newStatusNode]);
      setEdges((eds) => [...eds, ...newEdges]);
      return;
    }

    // 3. Add from edge (insert in between)
    if (sourceNode && targetNode) {
      let firstNewNode: Node;
      let secondNewNode: Node;

      if (sourceNode?.type === WorkflowNodeType.status) {
        const transitionId = `${WorkflowNodeType.transition}-${sourceNode.id}-${statusId}`;
        firstNewNode = {
          id: transitionId,
          type: WorkflowNodeType.transition,
          data: { event: NEW_EVENT_NAME, conditions: [] },
          position: sourceNode.position,
        };
        secondNewNode = {
          id: statusId,
          type: WorkflowNodeType.status,
          data: values,
          position: targetNode.position,
        };
      } else {
        const transitionId = `${WorkflowNodeType.transition}-${statusId}-${targetNode.id}`;
        firstNewNode = {
          id: statusId,
          type: WorkflowNodeType.status,
          data: values,
          position: sourceNode.position,
        };
        secondNewNode = {
          id: transitionId,
          type: WorkflowNodeType.transition,
          data: { event: NEW_EVENT_NAME, conditions: [] },
          position: targetNode.position,
        };
      }

      const newEdges: Edge[] = [
        {
          id: `e-${sourceNode.id}->${firstNewNode.id}`,
          source: sourceNode.id,
          target: firstNewNode.id,
          type: WorkflowNodeType.transition,
          ...(sourceNode.type === WorkflowNodeType.transition ? { markerEnd: { type: MarkerType.ArrowClosed } } : {}),
        },
        {
          id: `e-${firstNewNode.id}->${secondNewNode.id}`,
          source: firstNewNode.id,
          target: secondNewNode.id,
          type: WorkflowNodeType.transition,
          ...(sourceNode.type === WorkflowNodeType.status ? { markerEnd: { type: MarkerType.ArrowClosed } } : {}),
        },
        {
          id: `e-${secondNewNode.id}->${targetNode.id}`,
          source: secondNewNode.id,
          target: targetNode.id,
          type: WorkflowNodeType.transition,
          ...(sourceNode.type === WorkflowNodeType.transition ? { markerEnd: { type: MarkerType.ArrowClosed } } : {}),
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
