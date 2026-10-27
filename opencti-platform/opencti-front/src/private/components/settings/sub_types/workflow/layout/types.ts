import type { XYPosition } from 'reactflow';

// What the layout reads from a React Flow node or edge. Anything else on them is ignored.
export interface LayoutInputNode {
  id: string;
  type?: string;
  width?: number | null;
  height?: number | null;
}

export interface LayoutInputEdge {
  id: string;
  source: string;
  target: string;
}

export interface LayoutOptions {
  // [horizontal gap between nodes, vertical gap between rows], in pixels
  spacing: [number, number];
  // Node id of the saved initial status: drawn on the top row when present.
  initialStatusId?: string | null;
}

// Render hints written to `node.data.layout`. Never part of the saved workflow definition.
export interface LayoutNodeHints {
  backward: boolean;
  lane: 'left' | 'right' | null;
  rank: number;
}

export interface LayoutResult {
  positions: Map<string, XYPosition>; // top-left corner, React Flow convention
  nodeHints: Map<string, LayoutNodeHints>;
  routes: Map<string, XYPosition[]>; // absolute flow coordinates, axis-aligned segments
}

export interface GraphNode {
  id: string;
  type: string;
  w: number;
  h: number;
  order: number; // model order: index in the input array
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  order: number;
}

export interface Graph {
  nodes: Map<string, GraphNode>;
  list: GraphNode[];
  edges: GraphEdge[];
  outE: Map<string, GraphEdge[]>;
  inE: Map<string, GraphEdge[]>;
  maxHeight: number;
}

// A node of the layered (forward, acyclic) graph: a real node or a dummy point of a long edge.
export interface LayerNode {
  id: string;
  rank: number;
  w: number;
  h: number;
  dummy: boolean;
}

export interface Segment {
  u: string;
  v: string;
}

export interface RankedGraph {
  backEdges: Set<string>;
  backwardTransitions: Set<string>;
  forwardEdges: GraphEdge[];
  fOut: Map<string, GraphEdge[]>;
  fIn: Map<string, GraphEdge[]>;
  rank: Map<string, number>;
  layered: Map<string, LayerNode>;
  chains: Map<string, string[]>; // forward edge id -> [source, ...dummies, target]
  segments: Segment[]; // edges between adjacent rows of the layered graph
  up: Map<string, string[]>;
  down: Map<string, string[]>;
  maxRank: number;
}

export interface Ordering {
  layers: string[][];
  pos: Map<string, number>; // index of a layered node inside its row
  seed: Map<string, number>; // DFS preorder index
  treeKids: Map<string, string[]>; // DFS-tree children, in model order
  crossings: number;
}

export interface Placement {
  cx: number;
  cy: number;
  w: number;
  h: number;
  rank: number;
}

export type LaneSide = 'left' | 'right';

export interface NodeLaneItem {
  kind: 'node';
  id: string; // backward transition id
  ins: GraphEdge[];
  outs: GraphEdge[]; // every outgoing edge goes back up the graph
  to: string; // target of the first outgoing edge (self-loop check)
  row: number;
  selfLoop: boolean;
  r0: number;
  r1: number;
  order: number;
  side: LaneSide;
  sign: 1 | -1;
  lx: number;
}

export interface EdgeLaneItem {
  kind: 'edge';
  id: string; // back edge id (extra source of a forward multi-source transition)
  edge: GraphEdge;
  r0: number;
  r1: number;
  order: number;
  side: LaneSide;
  sign: 1 | -1;
  lx: number;
}

export type LaneItem = NodeLaneItem | EdgeLaneItem;
