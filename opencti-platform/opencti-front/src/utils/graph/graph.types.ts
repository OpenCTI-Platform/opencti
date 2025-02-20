import { ForceGraphProps } from 'react-force-graph-3d';

interface GraphElement {
  id: string
  name: string
  label: string
  disabled: boolean
  defaultDate: Date
  entity_type: string
  parent_types: string[]
  relationship_type: string
  isNestedInferred: boolean
  createdBy: { id: string, name: string }
  markedBy: { id: string, definition: string }[]
}

export interface GraphLink extends GraphElement {
  target: string | GraphNode
  target_id: string
  source: string | GraphNode
  source_id: string
  inferred: boolean
}

export interface GraphNode extends GraphElement {
  val: number
  color: string
  x: number
  y: number
  z: number
  fx?: number
  fy?: number
  fz?: number
  toId?: string
  toType?: string
  fromId?: string
  fromType?: string
  isObservable: boolean
  rawImg: string
  img: HTMLImageElement
  numberOfConnectedElement?: number
}

export const isGraphNode = (o: GraphNode | GraphLink): o is GraphNode => {
  return (o as GraphNode).img !== undefined;
};
export const isGraphLink = (o: GraphNode | GraphLink): o is GraphLink => {
  return (o as GraphLink).source_id !== undefined;
};

export type LibGraphProps = ForceGraphProps<GraphNode, GraphLink>;

export interface OctiGraphPositions {
  [key: string]: {
    id: string
    x: number
    y: number
    z?: number
  }
}

export interface GraphContainer {
  id: string
  confidence: unknown
  createdBy: unknown
  published: unknown
  objects: readonly unknown[]
  objectMarking: readonly unknown[]
}

// Stuff kept in URL and local storage.
export interface GraphState {
  mode3D: boolean
  modeTree: 'td' | 'lr' | null
  withForces: boolean
  selectFreeRectangle: boolean
  selectFree: boolean
  selectRelationshipMode: 'children' | 'parent' | 'deselect' | null
  showTimeRange: boolean
  disabledEntityTypes: string[]
  disabledCreators: string[]
  disabledMarkings: string[]
  zoom?: {
    k: number
    x: number
    y: number
  }
}
