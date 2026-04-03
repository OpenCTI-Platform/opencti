import { useCallback } from 'react';
import { useReactFlow } from 'reactflow';

const useDeleteElement = () => {
  const { setNodes, setEdges } = useReactFlow();

  const deleteElement = useCallback((id: string) => {
    // 1. Remove the node
    setNodes((nds) => nds.filter((node) => node.id !== id));

    // 2. Remove any edges connected to this node (source or target)
    setEdges((eds) => eds.filter((edge) => edge.source !== id && edge.target !== id));
  }, [setNodes, setEdges]);

  return deleteElement;
};

export default useDeleteElement;
