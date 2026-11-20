import { useEffect } from 'react';
import { type ReactFlowState, useReactFlow, useStore } from 'reactflow';
import { useFormatter } from '../../../../../components/i18n';
import { nameEdges } from '../utils/playbookEdgeNames';

// What the link names depend on: the links, the step names and the ports; a move changes none of them.
const namesSelector = (state: ReactFlowState) => {
  const nodes = [...state.nodeInternals.values()].map((n) => `${n.id}:${n.type}:${n.data?.name ?? ''}`).sort().join('|');
  const edges = state.edges.map((e) => `${e.id}:${e.source}:${e.sourceHandle ?? ''}>${e.target}:${e.ariaLabel ?? ''}`).join('|');
  return `${nodes}#${edges}`;
};

// Keeps every link of the canvas named after its steps (playbookEdgeAriaLabel), whatever added or
// changed it: the load, an insert, a rewiring, an undo.
const usePlaybookEdgeNames = () => {
  const { t_i18n } = useFormatter();
  const { getNodes, getEdges, setEdges } = useReactFlow();
  const key = useStore(namesSelector);
  useEffect(() => {
    const edges = getEdges();
    const named = nameEdges(edges, getNodes(), t_i18n);
    if (named !== edges) setEdges(named);
  }, [key, getNodes, getEdges, setEdges, t_i18n]);
};

export default usePlaybookEdgeNames;
