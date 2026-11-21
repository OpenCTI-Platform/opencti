export type LayoutDirection = 'TB' | 'LR';

export interface LayoutNode {
  id: string;
  width: number;
  height: number;
}

export interface LayoutEdge {
  source: string;
  target: string;
  /** Higher weight keeps the edge shorter and straighter. */
  weight: number;
}

export interface Position {
  x: number;
  y: number;
}

/** Positions are top-left corners, as React Flow expects. */
export interface LayoutEngine {
  layout: (nodes: LayoutNode[], edges: LayoutEdge[], direction: LayoutDirection) => Map<string, Position>;
}
