import { useCallback } from 'react';
import { useReactFlow } from 'reactflow';
import { deleteConnection } from '../edgeActions';

// Deletes one connection (see deleteConnection), reading the graph when it runs, like
// useDeleteElement and useAddStatus. The callback stays stable, so the edge menu context does not
// change on every graph edit.
const useDeleteConnection = () => {
  const { getNodes, getEdges, setNodes, setEdges } = useReactFlow();

  return useCallback((edgeId: string) => {
    const next = deleteConnection(getNodes(), getEdges(), edgeId);
    setNodes(next.nodes);
    setEdges(next.edges);
  }, [getNodes, getEdges, setNodes, setEdges]);
};

export default useDeleteConnection;
