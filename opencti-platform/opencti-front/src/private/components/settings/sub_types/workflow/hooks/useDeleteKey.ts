import { type KeyboardEvent, useCallback } from 'react';
import { useReactFlow } from 'reactflow';
import { deleteConnection } from '../edgeActions';
import { WorkflowNodeType } from '../utils';

// Backspace / Delete on the canvas, in place of React Flow's delete key (deleteKeyCode={null}),
// which removes elements raw. A selected transition edge follows deleteConnection, like the edge
// menu; a selected status goes with its edges, like the drawer's delete (useDeleteElement).
// Placeholders stay. Keys typed in a form field or in an open menu are left alone.
// Everything is computed from one read of the graph and applied once: React Flow runs a
// setNodes updater on its current nodes, so two updates in a row would overwrite each other.
const useDeleteKey = () => {
  const { getNodes, getEdges, setNodes, setEdges } = useReactFlow();

  return useCallback((event: KeyboardEvent) => {
    if (event.key !== 'Backspace' && event.key !== 'Delete') return;
    if ((event.target as HTMLElement).closest('input, textarea, [contenteditable="true"], [role="menu"]')) return;
    const edgeIds = getEdges().filter((e) => e.selected && e.type === WorkflowNodeType.transition).map((e) => e.id);
    const graph = edgeIds.reduce((g, id) => deleteConnection(g.nodes, g.edges, id), { nodes: getNodes(), edges: getEdges() });
    const statusIds = new Set(graph.nodes.filter((n) => n.selected && n.type === WorkflowNodeType.status).map((n) => n.id));
    if (edgeIds.length === 0 && statusIds.size === 0) return;
    setNodes(graph.nodes.filter((n) => !statusIds.has(n.id)));
    setEdges(graph.edges.filter((e) => !statusIds.has(e.source) && !statusIds.has(e.target)));
  }, [getNodes, getEdges, setNodes, setEdges]);
};

export default useDeleteKey;
