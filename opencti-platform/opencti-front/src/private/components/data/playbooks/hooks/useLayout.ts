import { useEffect, useRef } from 'react';
import { useReactFlow, useStore, useNodesInitialized, Node, Edge, ReactFlowState } from 'reactflow';
import { timer } from 'd3-timer';
import { layoutPlaybook, PlaybookLayoutComponent, PlaybookLayoutLink, PlaybookLayoutNode } from '../layout/layoutPlaybook';
import type { PlaybookLayoutDirection } from './usePlaybookLayoutMode';
import { outPorts, PLAYBOOK_CARD, portAddPosition } from '../types/nodes/playbookNodeGeometry';

// [gap between siblings, gap between ranks]: room for the port pills and the add buttons. The
// links turn on the middle line of the rank gap; the add button of a free port ends 8 px above it.
export const PLAYBOOK_LAYOUT_SPACING: [number, number] = [56, 104];
const ORIGIN_SIZE = { width: 240, height: 64 };

const options = { duration: 300 };
// Opening a playbook fits it, never above 100%: a one-step playbook is not blown up.
const INITIAL_FIT = { padding: 0.2, maxZoom: 1 };
// A layout direction change refits the view once the steps reach their new place.
const DIRECTION_REFIT_DELAY = options.duration + 50;

// Same input, same picture: the steps are placed by the pure layout of the playbook structure
// (nodes, links and the ports of their components), never from the array order of the store,
// and opening or refreshing a playbook writes nothing. The add buttons of free ports are not
// steps: they are drawn next to the port they extend, so they never push a step aside.
export const layoutNodes = (nodes: Node[], edges: Edge[], direction: PlaybookLayoutDirection = 'vertical'): Node[] => {
  if (nodes.length === 0) {
    return [];
  }
  const steps = nodes.filter((node) => node.type !== 'placeholder');
  const stepIds = new Set(steps.map((node) => node.id));
  const components = new Map<string, PlaybookLayoutComponent>();
  const layoutInput: PlaybookLayoutNode[] = steps.map((node) => {
    const component = node.data?.component as PlaybookLayoutComponent | undefined;
    if (component?.id) components.set(component.id, component);
    return { id: node.id, component_id: component?.id ?? '', position: node.position };
  });
  const links: PlaybookLayoutLink[] = edges
    .filter((edge) => stepIds.has(edge.source) && stepIds.has(edge.target))
    .map((edge) => ({ id: edge.id, from: { id: edge.source, port: edge.sourceHandle ?? 'out' }, to: { id: edge.target } }));
  const result = layoutPlaybook(layoutInput, links, [...components.values()], { mode: direction, nodeSize: PLAYBOOK_CARD, spacing: PLAYBOOK_LAYOUT_SPACING });

  const parentOf = new Map<string, Edge>();
  edges.forEach((edge) => {
    if (!stepIds.has(edge.target)) parentOf.set(edge.target, edge);
  });
  return nodes.map((node) => {
    if (node.type !== 'placeholder') {
      return { ...node, position: result.positions.get(node.id) ?? node.position };
    }
    const edge = parentOf.get(node.id);
    const parent = edge ? steps.find((step) => step.id === edge.source) : undefined;
    const parentPosition = parent ? result.positions.get(parent.id) : undefined;
    if (!edge || !parent || !parentPosition) {
      // The add button of an empty playbook: centred where the entry point will stand.
      return { ...node, position: { x: (PLAYBOOK_CARD.width - ORIGIN_SIZE.width) / 2, y: 0 } };
    }
    const ports = outPorts(parent.data?.component?.ports);
    const index = Math.max(0, ports.findIndex((port) => port.id === edge.sourceHandle));
    return { ...node, position: portAddPosition(parentPosition, index, ports.length, direction) };
  });
};

// The structure the layout depends on: a change of a name or a configuration does not move anything.
const structureSelector = (state: ReactFlowState) => {
  const nodeIds = [...state.nodeInternals.keys()].sort().join(',');
  const edgeIds = state.edges.map((e) => `${e.source}:${e.sourceHandle ?? ''}>${e.target}`).sort().join(',');
  return `${nodeIds}|${edgeIds}`;
};

const useLayout = (direction: PlaybookLayoutDirection = 'vertical') => {
  const initial = useRef(true);
  const fitted = useRef(false);
  const shownDirection = useRef(direction);
  const structure = useStore(structureSelector);
  const nodesInitialized = useNodesInitialized();
  const { getNodes, getNode, setNodes, getEdges, fitView } = useReactFlow();
  useEffect(() => {
    const nodes = getNodes();
    const edges = getEdges();
    const targetNodes = layoutNodes(nodes, edges, direction);
    if (initial.current) {
      // Opening a playbook: the steps stand at their place at once, no animation from the saved positions.
      initial.current = false;
      setNodes(targetNodes.map((node) => ({ id: node.id, position: node.position, data: { ...node.data }, type: node.type })));
      return undefined;
    }
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
        fitView({ duration: 200, padding: 0.2 });
      }
    });
    return () => {
      t.stop();
    };
  }, [structure, direction, getEdges, getNodes, getNode, setNodes, fitView]);
  // A direction change moves every step: the view is refitted the same way as on open, on its own
  // timer, so a re-render that stops the move animation never leaves a step outside the pane.
  const fitViewRef = useRef(fitView);
  fitViewRef.current = fitView;
  useEffect(() => {
    if (shownDirection.current === direction) return undefined;
    shownDirection.current = direction;
    const timeout = setTimeout(() => fitViewRef.current({ ...INITIAL_FIT, duration: 200 }), DIRECTION_REFIT_DELAY);
    return () => clearTimeout(timeout);
  }, [direction]);
  // A fit before the cards are measured has no bounds and leaves the default zoom: fit once they are.
  useEffect(() => {
    if (nodesInitialized && !fitted.current) {
      fitted.current = true;
      fitView(INITIAL_FIT);
    }
  }, [nodesInitialized, fitView]);
};

export default useLayout;
