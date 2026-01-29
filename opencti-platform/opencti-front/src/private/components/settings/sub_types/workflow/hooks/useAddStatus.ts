import { MarkerType, useReactFlow } from 'reactflow';
import type { Node, Edge } from 'reactflow';
import { colorPalette } from '../utils';
import type { Status } from '../utils';

const createPlaceholder = (parentStatusId: string) => {
  const pId = `placeholder-${parentStatusId}`;
  const pNode: Node = {
    id: pId,
    type: 'placeholder',
    data: {},
    position: { x: 0, y: 0 },
  };
  const pEdge: Edge = {
    id: `e-${parentStatusId}->${pId}`,
    source: parentStatusId,
    target: pId,
    markerEnd: { type: MarkerType.ArrowClosed, color: '#ffffff' },
    style: { strokeWidth: 0.5, strokeDasharray: '3 3', stroke: '#ffffff', opacity: 1 },
  };
  return { pNode, pEdge };
};

const useAddStatus = (selectedElement?: Edge | null) => {
  const { setNodes, setEdges, getNode, getNodes } = useReactFlow();

  const onClick = (values: Status): void => {
    if (!selectedElement) {
      console.error('No edge selected');
      return;
    }

    // TODO remove when status have color
    const index = getNodes().filter((n) => n.type === 'status').length + 1;
    const color = values?.color || colorPalette[index % colorPalette.length];

    const sourceNode = getNode(selectedElement.source);
    const targetNode = getNode(selectedElement.target);

    if (!sourceNode || !targetNode) {
      const newStatusNode: Node = {
        id: values.name,
        type: 'status',
        data: { ...values, color },
        position: { x: 0, y: 0 },
      };

      const { pNode, pEdge } = createPlaceholder(newStatusNode.id);

      setNodes((nds) => [...nds, newStatusNode, pNode]);
      setEdges((eds) => [...eds, pEdge]);
      return;
    };

    const newStatusName = values.name.toLowerCase().replace(/\s+/g, '-');

    let firstNewNode: Node;
    let secondNewNode: Node;

    // Determine the order: Status -> Transition -> Status -> Transition...
    if (sourceNode.type === 'status') {
    // Current: Status -> [New Transition] -> [New Status] -> Transition (Target)
      const transitionId = `transition-${sourceNode.id}-${newStatusName}`;
      const statusId = newStatusName;

      firstNewNode = {
        id: transitionId,
        type: 'transition',
        data: { event: 'NEW_EVENT', conditions: [] },
        position: { x: (sourceNode.position.x + targetNode.position.x) / 2, y: sourceNode.position.y + 100 },
      };
      secondNewNode = {
        id: statusId,
        type: 'status',
        data: { ...values, color },
        position: { x: (sourceNode.position.x + targetNode.position.x) / 2, y: sourceNode.position.y + 200 },
      };
    } else {
    // Current: Transition -> [New Status] -> [New Transition] -> Status (Target)
      const statusId = newStatusName;
      const transitionId = `transition-${statusId}-${targetNode.id}`;

      firstNewNode = {
        id: statusId,
        type: 'status',
        data: { ...values, color },
        position: { x: (sourceNode.position.x + targetNode.position.x) / 2, y: sourceNode.position.y + 100 },
      };
      secondNewNode = {
        id: transitionId,
        type: 'transition',
        data: { event: 'NEW_EVENT', conditions: [] },
        position: { x: (sourceNode.position.x + targetNode.position.x) / 2, y: sourceNode.position.y + 200 },
      };
    }

    // Create the 3 edges that replace the 1 clicked edge
    const newEdges: Edge[] = [
      {
        id: `e-${sourceNode.id}->${firstNewNode.id}`,
        source: sourceNode.id,
        target: firstNewNode.id,
        type: 'transition',
        ...(sourceNode.type === 'transition' ? { markerEnd: { type: MarkerType.ArrowClosed } } : {}) },
      {
        id: `e-${firstNewNode.id}->${secondNewNode.id}`,
        source: firstNewNode.id,
        target: secondNewNode.id,
        type: 'transition', ...(sourceNode.type === 'status' ? { markerEnd: { type: MarkerType.ArrowClosed } } : {}) },
      {
        id: `e-${secondNewNode.id}->${targetNode.id}`,
        source: secondNewNode.id,
        target: targetNode.id,
        type: 'transition', ...(sourceNode.type === 'transition' ? { markerEnd: { type: MarkerType.ArrowClosed } } : {}) },
    ];

    // Update Nodes
    setNodes((nds) => [...nds, firstNewNode, secondNewNode]);

    // Update Edges: Explicitly filter out the clicked edge by ID
    setEdges((eds) => {
      const filteredEdges = eds.filter((edge) => edge.id !== selectedElement.id);
      return [...filteredEdges, ...newEdges];
    });
  };

  return onClick;
};

export default useAddStatus;
