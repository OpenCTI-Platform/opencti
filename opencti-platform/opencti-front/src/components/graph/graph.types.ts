import { ForceGraphProps } from 'react-force-graph-3d';
import { DefaultMarking } from '@components/settings/marking_definitions/markingDefinition.types';
import type { ObjectToParse } from './utils/useGraphParser';
import type { GraphPath } from './utils/graphFocus';

interface GraphElement {
  id: string;
  name: string;
  label: string;
  disabled: boolean;
  defaultDate: Date;
  entity_type: string;
  parent_types: string[];
  relationship_type: string;
  isNestedInferred: boolean;
  createdBy: { id: string; name: string };
  markedBy: { id: string; definition: string; x_opencti_color?: string | null }[];
  confidence?: number | null;
  /**
   * The object received from the query, untouched: badge providers and quick actions read their
   * own fields from it (soft checks), whatever the graph itself uses.
   */
  raw?: ObjectToParse;
}

export interface GraphLink extends GraphElement {
  target: string | GraphNode;
  target_id: string;
  source: string | GraphNode;
  source_id: string;
  inferred: boolean;
  /** A link drawn towards a group node: the number of relationships of the graph it stands for. */
  represents?: number;
}

export interface GraphNode extends GraphElement {
  val: number;
  color: string;
  x: number;
  y: number;
  z: number;
  fx?: number;
  fy?: number;
  fz?: number;
  toId?: string;
  toType?: string;
  fromId?: string;
  fromType?: string;
  isObservable: boolean;
  rawImg: string;
  img: HTMLImageElement;
  numberOfConnectedElement?: number;
  /** A group node standing for every entity of one type, collapsed by the reader. */
  groupOf?: { entityType: string; memberIds: string[] };
  /** An entity the reader may not see (markings, organization): drawn with a dashed outline and named "Restricted". */
  isRestricted?: boolean;
}

export const isGraphNode = (o: GraphNode | GraphLink): o is GraphNode => {
  return (o as GraphNode).img !== undefined;
};
export const isGraphLink = (o: GraphNode | GraphLink): o is GraphLink => {
  return (o as GraphLink).source_id !== undefined;
};

/**
 * Knowledge an inference rule made, which the graph neither edits nor removes: a member it added to
 * the container, or a relationship it created, drawn as a link or, as the end of a nested
 * relationship, as a node (its own flag is then only in the object received).
 */
export const isInferredNode = (node: GraphNode) => node.isNestedInferred || !!node.raw?.is_inferred;
export const isInferredLink = (link: GraphLink) => link.inferred || link.isNestedInferred;

export type LibGraphProps = ForceGraphProps<GraphNode, GraphLink>;

export interface OctiGraphPositions {
  [key: string]: {
    id: string;
    x: number;
    y: number;
    z?: number;
  };
}

export interface GraphEntity {
  id: string;
  confidence?: number | null | undefined;
  createdBy?: unknown | null | undefined;
  published?: string | null | undefined;
  objectMarking?: readonly DefaultMarking[] | null | undefined;
}

/** Deterministic layouts other than the tree modes: by entity tier, or rings around one node. */
export type GraphLayoutMode = 'tiers' | 'radial';

// Stuff kept in URL and local storage.
export interface GraphState {
  mode3D: boolean;
  modeTree: 'td' | 'lr' | null;
  layoutMode?: GraphLayoutMode | null;
  /** Centre of the radial layout; the most connected node when unset. */
  layoutCentreId?: string | null;
  /** Entities hidden from the view by the reader (not removed from the data). */
  hiddenNodeIds?: string[];
  /** Entity types drawn as a single group node. */
  collapsedEntityTypes?: string[];
  /** Relationship types hidden from the view through the legend. */
  disabledRelationshipTypes?: string[];
  /** Legend open, or minimized to its pill; a preference of the user, not saved with the graph. */
  showLegend?: boolean;
  /** Shortest path highlighted between two nodes. */
  highlightedPath?: GraphPath | null;
  withForces: boolean;
  selectFreeRectangle: boolean;
  selectFree: boolean;
  selectRelationshipMode: 'children' | 'parent' | 'deselect' | null;
  correlationMode: 'all' | 'observables' | null;
  showTimeRange: boolean;
  showLinearProgress: boolean;
  loadingTotal?: number;
  loadingCurrent?: number;
  disabledEntityTypes: string[];
  disabledCreators: string[];
  disabledMarkings: string[];
  selectedTimeRangeInterval?: [Date, Date];
  selectedNodes: GraphNode[];
  selectedLinks: GraphLink[];
  detailsPreviewSelected?: GraphNode | GraphLink;
  search?: string;
  zoom?: {
    k: number;
    x: number;
    y: number;
  };
  // Stuff put inside context because the dialog can be
  // opened by other source than click in toolbar.
  isAddRelationOpen: boolean; // (cf <RelationSelection />)
  isExpandOpen: boolean; // (cf Graph.tsx)
}
