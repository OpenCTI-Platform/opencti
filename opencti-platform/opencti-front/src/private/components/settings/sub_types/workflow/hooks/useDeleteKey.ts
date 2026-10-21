import { useEffect } from 'react';
import { useReactFlow } from 'reactflow';
import { deleteConnection } from '../edgeActions';
import { WorkflowNodeType } from '../utils';

// Backspace / Delete, in place of React Flow's delete key (deleteKeyCode={null}), which removes
// elements raw. A selected transition edge follows deleteConnection, like the edge menu; a selected
// status goes with its edges, like the drawer's delete (useDeleteElement). Placeholders stay.
// Like React Flow's key, it listens on the document, so it also works when nothing has focus (after
// a pane click or a box select). It ignores keys from outside the canvas (the drawer, a dialog, a
// menu in a portal) and keys typed in a form field or an open menu.
// Everything is computed from one read of the graph and applied once: React Flow runs a
// setNodes updater on its current nodes, so two updates in a row would overwrite each other.
const useDeleteKey = () => {
  const { getNodes, getEdges, setNodes, setEdges } = useReactFlow();

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key !== 'Backspace' && event.key !== 'Delete') return;
      const target = event.target as HTMLElement;
      if (target !== document.body && !target.closest('.react-flow')) return;
      if (target.closest('input, textarea, select, [contenteditable="true"], [role="menu"]')) return;
      const edgeIds = getEdges().filter((e) => e.selected && e.type === WorkflowNodeType.transition).map((e) => e.id);
      const graph = edgeIds.reduce((g, id) => deleteConnection(g.nodes, g.edges, id), { nodes: getNodes(), edges: getEdges() });
      const statusIds = new Set(graph.nodes.filter((n) => n.selected && n.type === WorkflowNodeType.status).map((n) => n.id));
      if (edgeIds.length === 0 && statusIds.size === 0) return;
      setNodes(graph.nodes.filter((n) => !statusIds.has(n.id)));
      setEdges(graph.edges.filter((e) => !statusIds.has(e.source) && !statusIds.has(e.target)));
    };
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [getNodes, getEdges, setNodes, setEdges]);
};

export default useDeleteKey;
