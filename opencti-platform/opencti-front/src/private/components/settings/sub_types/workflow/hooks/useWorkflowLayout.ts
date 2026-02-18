import { useEffect } from 'react';
import { type Node, type Edge, useReactFlow, useNodesInitialized, useStore, getIncomers, Position } from 'reactflow';
import { type HierarchyPointNode, stratify, tree } from 'd3-hierarchy';

type NodeWithPosition = Node & { x: number; y: number };
export type Direction = 'TB' | 'LR' | 'RL' | 'BT';

export type LayoutOptions = {
  direction: Direction;
  spacing: [number, number];
};

const getSourceHandlePosition = (direction: Direction) => {
  switch (direction) {
    case 'TB':
      return Position.Bottom;
    case 'BT':
      return Position.Top;
    case 'LR':
      return Position.Right;
    case 'RL':
      return Position.Left;
  }
};

const getTargetHandlePosition = (direction: Direction) => {
  switch (direction) {
    case 'TB':
      return Position.Top;
    case 'BT':
      return Position.Bottom;
    case 'LR':
      return Position.Left;
    case 'RL':
      return Position.Right;
  }
};

// Initialize the tree layout (see https://observablehq.com/@d3/tree for examples)
const layout = tree<NodeWithPosition>()
  // By default, d3 hierarchy spaces nodes that do not share a common parent quite
  // far apart. We think it looks a bit nicer (and more similar to the other layouting
  // algorithms) if we fix that distance to a uniform `1`.
  .separation(() => 1);

// D3 Hierarchy expects a single root node in a flow. Because we can't always
// guarantee that, we create a fake root node here and will make sure any real
// nodes without an incoming edge will get connected to this fake root node.
const rootNode = {
  id: 'd3-hierarchy-root',
  x: 0,
  y: 0,
  position: { x: 0, y: 0 },
  data: {},
};

const layoutAlgorithm = async (nodes: Node[], edges: Edge[], options = { direction: 'TB', spacing: [50, 50] }) => {
  const initialNodes = [] as NodeWithPosition[];
  let maxNodeWidth = 0;
  let maxNodeHeight = 0;

  for (const node of nodes) {
    const nodeWithPosition = { ...node, ...node.position };

    initialNodes.push(nodeWithPosition);
    maxNodeWidth = Math.max(maxNodeWidth, node.width ?? 0);
    maxNodeHeight = Math.max(maxNodeHeight, node.height ?? 0);
  }

  // When the layout is horizontal, we swap the width and height measurements we
  // pass to the layout algorithm so things stay spaced out nicely. By adding the
  // amount of spacing to each size we can fake padding between nodes.
  const nodeSize = [maxNodeWidth + options.spacing[0], maxNodeHeight + options.spacing[1]];
  layout.nodeSize(nodeSize as [number, number]);

  const getParentId = (node: Node) => {
    if (node.id === rootNode.id) {
      return undefined;
    }

    const incomers = getIncomers(node, nodes, edges);

    // If there are no incoming edges, we say this node is connected to the fake
    // root node to prevent having multiple root nodes in the layout. If there
    // are multiple incoming edges, only the first one will be used!
    return incomers[0]?.id || rootNode.id;
  };

  const hierarchy = stratify<NodeWithPosition>()
    .id((d) => d.id)
    .parentId(getParentId)([rootNode, ...initialNodes]);

  // We create a map of the laid out nodes here to avoid multiple traversals when
  // looking up a node's position later on.
  const root = layout(hierarchy);
  const layoutNodes = new Map<string, HierarchyPointNode<NodeWithPosition>>();
  for (const node of root) {
    layoutNodes.set(node.id!, node);
  }

  const nextNodes = nodes.map((node) => {
    const { x, y } = layoutNodes.get(node.id)!;
    const position = { x, y };
    // The layout algorithm uses the node's center point as its origin, so we need
    // to offset that position because React Flow uses the top left corner as a
    // node's origin by default.
    const offsetPosition = {
      x: position.x - (node.width ?? 0) / 2,
      y: position.y - (node.height ?? 0) / 2,
    };

    return { ...node, position: offsetPosition };
  });

  return { nodes: nextNodes, edges };
};

const useAutoLayout = (options: LayoutOptions) => {
  const { setNodes, setEdges } = useReactFlow();
  const nodesInitialized = useNodesInitialized();
  // Here we are storing a map of the nodes and edges in the flow. By using a
  // custom equality function as the second argument to `useStore`, we can make
  // sure the layout algorithm only runs when something has changed that should
  // actually trigger a layout change.
  const elements = useStore(
    (state) => ({
      nodeMap: state.nodeInternals,
      edgeMap: state.edges.reduce(
        (acc, edge) => acc.set(edge.id, edge),
        new Map(),
      ),
    }),
    // The compare elements function will only update `elements` if something has
    // changed that should trigger a layout. This includes changes to a node's
    // dimensions, the number of nodes, or changes to edge sources/targets.
    compareElements,
  );

  useEffect(() => {
    // Only run the layout if there are nodes and they have been initialized with
    // their dimensions
    if (!nodesInitialized || elements.nodeMap.size === 0) {
      return;
    }

    // The callback passed to `useEffect` cannot be `async` itself, so instead we
    // create an async function here and call it immediately afterwards.
    const runLayout = async () => {
      const nodes = Array.from(elements.nodeMap.values());
      const edges = Array.from(elements.edgeMap.values());

      const { nodes: nextNodes, edges: nextEdges } = await layoutAlgorithm(
        nodes,
        edges,
        options,
      );

      // Mutating the nodes and edges directly here is fine because we expect our
      // layouting algorithms to return a new array of nodes/edges.
      for (const node of nextNodes) {
        node.style = { ...node.style, opacity: 1 };
        node.sourcePosition = getSourceHandlePosition(options.direction);
        node.targetPosition = getTargetHandlePosition(options.direction);
      }

      for (const edge of edges) {
        edge.style = { ...edge.style, opacity: 1 };
      }

      setNodes(nextNodes);
      setEdges(nextEdges);
    };

    runLayout();
  }, [nodesInitialized, elements, setNodes, setEdges]);
};

export default useAutoLayout;

type Elements = {
  nodeMap: Map<string, Node>;
  edgeMap: Map<string, Edge>;
};

const compareElements = (xs: Elements, ys: Elements) => {
  return (
    compareNodes(xs.nodeMap, ys.nodeMap) && compareEdges(xs.edgeMap, ys.edgeMap)
  );
};

const compareNodes = (xs: Map<string, Node>, ys: Map<string, Node>) => {
  // the number of nodes changed, so we already know that the nodes are not equal
  if (xs.size !== ys.size) return false;

  for (const [id, x] of xs.entries()) {
    const y = ys.get(id);

    // the node doesn't exist in the next state so it just got added
    if (!y) return false;
    // We don't want to force a layout change while a user might be resizing a
    // node, so we only compare the dimensions if the node is not currently
    // being resized.
    //
    // We early return here instead of using a `continue` because there's no
    // scenario where we'd want nodes to start moving around *while* a user is
    // trying to resize a node or move it around.
    if (x.resizing || x.dragging) return true;
    if (x.width !== y.width || x.height !== y.height) return false;
  }

  return true;
};

const compareEdges = (xs: Map<string, Edge>, ys: Map<string, Edge>) => {
  // the number of edges changed, so we already know that the edges are not equal
  if (xs.size !== ys.size) return false;

  for (const [id, x] of xs.entries()) {
    const y = ys.get(id);

    // the edge doesn't exist in the next state so it just got added
    if (!y) return false;
    if (x.source !== y.source || x.target !== y.target) return false;
    if (x?.sourceHandle !== y?.sourceHandle) return false;
    if (x?.targetHandle !== y?.targetHandle) return false;
  }

  return true;
};
