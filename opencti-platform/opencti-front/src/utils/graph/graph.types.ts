interface GraphElement {
  id: string
  name: string
  label: string
  disabled:boolean
  defaultDate: Date
  entity_type: string
  parent_types: string[]
  relationship_type: string
  isNestedInferred: boolean
  createdBy: { id: string, name: string }
  markedBy: { id: string, definition: string }[]
}

export interface GraphLink extends GraphElement {
  target: string
  target_id: string
  source: string
  source_id: string
  inferred: boolean
}

export interface GraphNode extends GraphElement {
  val: number
  color: string
  toId?: string
  toType?: string
  fromId?: string
  fromType?: string
  fx: number | null
  fy: number | null
  isObservable: boolean
  rawImg: string
  img: HTMLImageElement
  numberOfConnectedElement?: number
}

export interface GraphData {
  [key: string]: {
    id: string
    x: number | null
    y: number | null
  }
}

export interface GraphState {
  mode3D: boolean
  modeTree: 'vertical' | 'horizontal' | null
  withForces: boolean
  selectFreeRectangle: boolean
  selectFree: boolean
  selectRelationshipMode: 'children' | 'parent' | 'deselect' | null
  showTimeRange: boolean
}
