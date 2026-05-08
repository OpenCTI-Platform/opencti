import { useEffect } from 'react';
import { type Node, type Edge, useReactFlow, useNodesInitialized, useStore, getIncomers, Position } from 'reactflow';
import { type HierarchyPointNode, stratify, tree } from 'd3-hierarchy';
import { NODE_SIZE } from '../utils';

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

  // First pass: Build a temporary hierarchy to identify backward transitions
  const tempRoot = layout(hierarchy);
  const tempLayoutNodes = new Map<string, HierarchyPointNode<NodeWithPosition>>();
  tempRoot.each((node) => {
    tempLayoutNodes.set(node.id!, node);
  });

  // Helper function to check if targetNode is an ancestor of sourceNode
  const isAncestor = (targetNodeId: string, sourceNodeId: string, layoutMap: Map<string, HierarchyPointNode<NodeWithPosition>>): boolean => {
    const sourceHierarchyNode = layoutMap.get(sourceNodeId);
    if (!sourceHierarchyNode) return false;

    let current = sourceHierarchyNode.parent;
    while (current) {
      if (current.id === targetNodeId) return true;
      current = current.parent;
    }
    return false;
  };

  // Identify backward transitions (transitions whose target is an ancestor of their source)
  const backwardTransitions = new Set<string>();
  for (const node of initialNodes) {
    if (node.type === 'transition') {
      const outgoingEdge = edges.find((edge) => edge.source === node.id);
      const incomingEdge = edges.find((edge) => edge.target === node.id);

      if (outgoingEdge && incomingEdge) {
        const sourceStatusId = incomingEdge.source;
        const targetStatusId = outgoingEdge.target;

        // Check if this is a backward transition
        if (isAncestor(targetStatusId, sourceStatusId, tempLayoutNodes)) {
          backwardTransitions.add(node.id);
        }
      }
    }
  }

  // Second pass: Build hierarchy excluding backward transitions
  // This ensures D3 only spaces forward transitions horizontally
  const forwardNodes = initialNodes.filter((node) => !backwardTransitions.has(node.id));
  const forwardHierarchy = stratify<NodeWithPosition>()
    .id((d) => d.id)
    .parentId(getParentId)([rootNode, ...forwardNodes]);

  // Apply layout to the filtered hierarchy
  const root = layout(forwardHierarchy);
  const layoutNodes = new Map<string, HierarchyPointNode<NodeWithPosition>>();
  root.each((node) => {
    layoutNodes.set(node.id!, node);
  });

  const nextNodes = nodes.map((node) => {
    // Handle backward transitions separately - position them at midpoint
    if (backwardTransitions.has(node.id)) {
      const outgoingEdge = edges.find((edge) => edge.source === node.id);
      const incomingEdge = edges.find((edge) => edge.target === node.id);

      if (outgoingEdge && incomingEdge) {
        const sourceStatusId = incomingEdge.source;
        const targetStatusId = outgoingEdge.target;

        const sourcePos = layoutNodes.get(sourceStatusId);
        const targetPos = layoutNodes.get(targetStatusId);

        if (sourcePos && targetPos) {
          // Determine if source is in left or right branch by comparing to root
          const rootX = root.x;
          const isLeftBranch = sourcePos.x < rootX;

          // Alternate positioning: left branch gets negative offset, right branch gets positive
          const horizontalOffset = isLeftBranch
            ? -NODE_SIZE.width * 2
            : NODE_SIZE.width * 2;

          // Position the transition node in the middle between source and target
          const position = {
            x: ((sourcePos.x + targetPos.x) / 2) + horizontalOffset,
            y: (sourcePos.y + targetPos.y) / 2,
          };

          const offsetPosition = {
            x: position.x - (node.width ?? 0) / 2,
            y: position.y - (node.height ?? 0) / 2,
          };

          return {
            ...node,
            position: offsetPosition,
          };
        }
      }
    }

    // For all other nodes (forward transitions and status nodes), use D3 layout
    const layoutNode = layoutNodes.get(node.id);
    if (layoutNode) {
      const { x, y } = layoutNode;
      const offsetPosition = {
        x: x - (node.width ?? 0) / 2,
        y: y - (node.height ?? 0) / 2,
      };

      return {
        ...node,
        position: offsetPosition,
      };
    }

    // Fallback - should not happen
    return node;
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

  Array.from(xs.entries()).forEach(([id, x]) => {
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
  });

  return true;
};

const compareEdges = (xs: Map<string, Edge>, ys: Map<string, Edge>) => {
  // the number of edges changed, so we already know that the edges are not equal
  if (xs.size !== ys.size) return false;

  Array.from(xs.entries()).forEach(([id, x]) => {
    const y = ys.get(id);

    // the edge doesn't exist in the next state so it just got added
    if (!y) return false;
    if (x.source !== y.source || x.target !== y.target) return false;
    if (x?.sourceHandle !== y?.sourceHandle) return false;
    if (x?.targetHandle !== y?.targetHandle) return false;
  });

  return true;
};
