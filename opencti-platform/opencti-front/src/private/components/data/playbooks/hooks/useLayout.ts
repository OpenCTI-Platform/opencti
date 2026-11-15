import { useEffect, useRef } from 'react';
import { useReactFlow, useStore, Node, Edge, ReactFlowState } from 'reactflow';
import { timer } from 'd3-timer';
import { layoutPlaybook, PlaybookLayoutComponent, PlaybookLayoutLink, PlaybookLayoutMode, PlaybookLayoutNode } from '../layout/layoutPlaybook';

// Sibling pitch 250 px and rank pitch 175 px, the spacing of the previous tree layout.
const NODE_SIZE = { width: 220, height: 80 };
const SPACING: [number, number] = [30, 95];
const PLACEHOLDER_COMPONENT = '__placeholder';

const options = { duration: 300 };

// Same input, same picture: the positions come from the pure layout of the playbook structure
// (nodes, links and the ports of their components), never from the array order of the store,
// and opening or refreshing a playbook writes nothing.
export const layoutNodes = (nodes: Node[], edges: Edge[], mode: PlaybookLayoutMode = 'vertical'): Node[] => {
  if (nodes.length === 0) {
    return [];
  }
  const components = new Map<string, PlaybookLayoutComponent>();
  const layoutNodesInput: PlaybookLayoutNode[] = nodes.map((node) => {
    const component = node.data?.component as PlaybookLayoutComponent | undefined;
    if (node.type !== 'placeholder' && component?.id) {
      components.set(component.id, component);
      return { id: node.id, component_id: component.id, position: node.position };
    }
    return { id: node.id, component_id: PLACEHOLDER_COMPONENT, position: node.position };
  });
  const links: PlaybookLayoutLink[] = edges.map((edge) => ({
    id: edge.id,
    from: { id: edge.source, port: edge.sourceHandle ?? 'out' },
    to: { id: edge.target },
  }));
  const result = layoutPlaybook(layoutNodesInput, links, [...components.values()], { mode, nodeSize: NODE_SIZE, spacing: SPACING });
  return nodes.map((node) => ({ ...node, position: result.positions.get(node.id) ?? node.position }));
};

// The structure the layout depends on: a change of a name or a configuration does not move anything.
const structureSelector = (state: ReactFlowState) => {
  const nodeIds = [...state.nodeInternals.keys()].sort().join(',');
  const edgeIds = state.edges.map((e) => `${e.source}:${e.sourceHandle ?? ''}>${e.target}`).sort().join(',');
  return `${nodeIds}|${edgeIds}`;
};

const useLayout = () => {
  const initial = useRef(true);
  const structure = useStore(structureSelector);
  const { getNodes, getNode, setNodes, getEdges, fitView } = useReactFlow();
  useEffect(() => {
    const nodes = getNodes();
    const edges = getEdges();
    const targetNodes = layoutNodes(nodes, edges);
    const transitions = targetNodes.map((node) => ({
      node,
      // where the node is now, and where the layout places it
      from: getNode(node.id)?.position || node.position,
      to: node.position,
    }));
    const t = timer((elapsed: number) => {
      const s = Math.min(1, elapsed / options.duration);
      setNodes(transitions.map(({ node, from, to }) => ({
        id: node.id,
        position: { x: from.x + (to.x - from.x) * s, y: from.y + (to.y - from.y) * s },
        data: { ...node.data },
        type: node.type,
      })));
      if (elapsed > options.duration) {
        t.stop();
        if (!initial.current) {
          fitView({ duration: 200, padding: 0.2 });
        }
        initial.current = false;
      }
    });
    return () => {
      t.stop();
    };
  }, [structure, getEdges, getNodes, getNode, setNodes, fitView]);
};

export default useLayout;
