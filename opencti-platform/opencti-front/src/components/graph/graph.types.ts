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

export interface GraphEntity {
  id: string
  confidence?: number | null | undefined
  createdBy?: unknown | null | undefined
  published?: unknown | null | undefined
  objectMarking?: readonly unknown[] | null | undefined
}

// Stuff kept in URL and local storage.
export interface GraphState {
  mode3D: boolean
  modeTree: 'td' | 'lr' | null
  withForces: boolean
  selectFreeRectangle: boolean
  selectFree: boolean
  selectRelationshipMode: 'children' | 'parent' | 'deselect' | null
  correlationMode: 'all' | 'observables' | null
  showTimeRange: boolean
  showLinearProgress: boolean
  loadingTotal?: number
  loadingCurrent?: number
  disabledEntityTypes: string[]
  disabledCreators: string[]
  disabledMarkings: string[]
  selectedTimeRangeInterval?: [Date, Date]
  selectedNodes: GraphNode[]
  selectedLinks: GraphLink[]
  detailsPreviewSelected?: GraphNode | GraphLink
  search?: string
  zoom?: {
    k: number
    x: number
    y: number
  }
  // Put inside context because the dialog to create relationship can be
  // opened by other source than click in toolbar (cf <RelationSelection />).
  isAddRelationOpen: boolean
}
