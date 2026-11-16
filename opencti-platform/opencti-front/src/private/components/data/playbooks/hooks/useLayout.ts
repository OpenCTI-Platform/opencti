import { useCallback, useEffect, useRef, useState } from 'react';
import { useReactFlow, useStore, useNodesInitialized, Node, Edge, ReactFlowState, Viewport } from 'reactflow';
import { timer } from 'd3-timer';
import { layoutPlaybook, PlaybookLayoutComponent, PlaybookLayoutLink, PlaybookLayoutNode } from '../layout/layoutPlaybook';
import type { PlaybookLayoutDirection } from './usePlaybookLayoutMode';
import { outPorts, PLAYBOOK_CARD, portAddPosition } from '../types/nodes/playbookNodeGeometry';
import { PLAYBOOK_LANDING, playbookLandingViewport, playbookMiniMapClear } from '../utils/playbookLanding';

// [gap between siblings, gap between ranks]: room for the port pills and the add buttons. The
// links turn on the middle line of the rank gap; the add button of a free port ends 8 px above it.
export const PLAYBOOK_LAYOUT_SPACING: [number, number] = [56, 104];
const ORIGIN_SIZE = { width: 240, height: 64 };

const options = { duration: 300 };
// Opening a playbook fits it, never above 100% and never under a readable zoom (utils/playbookLanding).
const INITIAL_FIT = { padding: PLAYBOOK_LANDING.padding, maxZoom: PLAYBOOK_LANDING.maxZoom };
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

// The landing of a playbook in a pane: the viewport it opens on (null: a fit) and whether the minimap
// may be drawn there, both read on the positions the layout gives in this direction, never on the
// positions the store holds at that moment (saved ones, or the other direction's on a first open).
export const playbookLanding = (nodes: Node[], edges: Edge[], pane: { width: number; height: number }, direction: PlaybookLayoutDirection) => {
  const laid = layoutNodes(nodes, edges, direction);
  const viewport = playbookLandingViewport(laid, pane, direction);
  return { laid, viewport, miniMapClear: (at: Viewport) => playbookMiniMapClear(laid, at, pane) };
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
  const { getNodes, getNode, setNodes, getEdges, fitView, setViewport, getViewport } = useReactFlow();
  const paneWidth = useStore((state: ReactFlowState) => state.width);
  const paneHeight = useStore((state: ReactFlowState) => state.height);
  // The landing view of the playbook: a fit when the cards stay readable, else the readable zoom on
  // the entry point (a large playbook is explored from its start, the fit button still shows it whole).
  // The minimap is drawn once a landing leaves every card clear of its box, or once the user pans or
  // zooms: a landing never hides a card or its menu under the minimap.
  const [miniMapShown, setMiniMapShown] = useState(false);
  // Once the user moves the view, a pane resize no longer lands it again and the minimap stays.
  const userMoved = useRef(false);
  const land = useRef<(duration?: number) => void>(() => undefined);
  land.current = (duration?: number) => {
    const pane = { width: paneWidth, height: paneHeight };
    const { viewport, miniMapClear } = playbookLanding(getNodes(), getEdges(), pane, direction);
    if (viewport) setViewport(viewport, duration ? { duration } : undefined);
    else fitView(duration ? { ...INITIAL_FIT, duration } : INITIAL_FIT);
    const settle = () => {
      if (!userMoved.current) setMiniMapShown(miniMapClear(viewport ?? getViewport()));
    };
    if (viewport || !duration) settle();
    else setTimeout(settle, duration + 20);
  };
  // Only a move the user starts (wheel, drag, pinch) carries an event; the landings carry none.
  const onMoveStart = useCallback((event: unknown) => {
    if (event) {
      userMoved.current = true;
      setMiniMapShown(true);
    }
  }, []);
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
        fitView({ ...INITIAL_FIT, duration: 200 });
      }
    });
    return () => {
      t.stop();
    };
  }, [structure, direction, getEdges, getNodes, getNode, setNodes, fitView]);
  // A direction change moves every step: the view is refitted the same way as on open, on its own
  // timer, so a re-render that stops the move animation never leaves a step outside the pane.
  useEffect(() => {
    if (shownDirection.current === direction) return undefined;
    shownDirection.current = direction;
    // A layout switch is a new landing: the minimap is checked again on the new picture.
    userMoved.current = false;
    const timeout = setTimeout(() => land.current(200), DIRECTION_REFIT_DELAY);
    return () => clearTimeout(timeout);
  }, [direction]);
  // A fit before the cards are measured has no bounds and leaves the default zoom: land once they are.
  // The canvas takes its height after the first frame and follows the window: until the user moves
  // the view, every new pane size lands it again, so the entry point and the minimap check always
  // use the pane as it is drawn (a horizontal landing is centred on the pane height).
  useEffect(() => {
    if (!nodesInitialized || paneWidth <= 0 || paneHeight <= 0) return;
    if (fitted.current && userMoved.current) return;
    fitted.current = true;
    land.current();
  }, [nodesInitialized, paneWidth, paneHeight]);
  return { miniMapShown, onMoveStart };
};

export default useLayout;
