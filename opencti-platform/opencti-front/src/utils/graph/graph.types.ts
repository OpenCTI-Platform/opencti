import { ForceGraphProps } from 'react-force-graph-2d';

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
  fx?: number
  fy?: number
  toId?: string
  toType?: string
  fromId?: string
  fromType?: string
  isObservable: boolean
  rawImg: string
  img: HTMLImageElement
  numberOfConnectedElement?: number
}

export interface OctiGraphPositions {
  [key: string]: {
    id: string
    x: number
    y: number
  }
}

export type LibGraphProps = ForceGraphProps<GraphNode, GraphLink>;
