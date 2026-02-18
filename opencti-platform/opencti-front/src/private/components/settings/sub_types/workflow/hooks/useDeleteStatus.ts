import { useCallback } from 'react';
import { useReactFlow } from 'reactflow';

const useDeleteStatus = () => {
  const { setNodes, setEdges, getNode, getNodes, getEdges } = useReactFlow();

  const deleteStatus = useCallback((nodeId: string) => {
    // 1. Get current snapshots
    const nodes = getNodes();
    const edges = getEdges();

    const targetNode = nodes.find((n) => n.id === nodeId);
    if (!targetNode || targetNode.type !== 'status') return;

    // 2. Identify all related nodes to wipe out in one go
    const relatedEdges = edges.filter(
      (edge) => edge.source === nodeId || edge.target === nodeId,
    );

    const transitionNodeIdsToRemove = relatedEdges
      .map((edge) => (edge.source === nodeId ? edge.target : edge.source))
      .filter((id) => getNode(id)?.type === 'transition');

    const placeholderId = `placeholder-${nodeId}`;

    const allNodeIdsToRemove = [
      nodeId,
      ...transitionNodeIdsToRemove,
      placeholderId,
    ];

    // 3. Perform a SINGLE update for nodes and edges
    // This reduces the number of render cycles
    setNodes((nds) => nds.filter((n) => !allNodeIdsToRemove.includes(n.id)));
    setEdges((eds) =>
      eds.filter(
        (e) =>
          !allNodeIdsToRemove.includes(e.source)
          && !allNodeIdsToRemove.includes(e.target),
      ),
    );
  }, [getNodes, getEdges, getNode, setNodes, setEdges]);

  return deleteStatus;
};

export default useDeleteStatus;
