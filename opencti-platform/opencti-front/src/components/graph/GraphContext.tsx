import React, { ReactNode, useContext, createContext, useState, useEffect, useMemo, Dispatch, SetStateAction, MutableRefObject, useRef } from 'react';
import { useLocation, useNavigate } from 'react-router';
import * as graph2d from 'react-force-graph-2d';
import * as graph3d from 'react-force-graph-3d';
import { buildViewParamsFromUrlAndStorage, saveViewParameters } from '../../utils/ListParameters';
import { GraphNode, GraphLink, LibGraphProps, GraphState, OctiGraphPositions } from './graph.types';
import { useFormatter } from '../i18n';
import useGraphParser, { ObjectToParse } from './utils/useGraphParser';
import { computeTimeRangeInterval, computeTimeRangeValues, GraphTimeRange } from './utils/graphTimeRange';
import { graphStateToLocalStorage, normalizeGraphStateParams } from './utils/graphUtils';
import { readLegendOpen, writeLegendOpen } from './utils/graphLegendPreference';
import { readHiddenNodeIds, writeHiddenNodeIds } from './utils/graphHiddenNodes';
import { UserContext } from '../../utils/hooks/useAuth';

type Setter<T> = Dispatch<SetStateAction<T>>;

export type GraphRef2D = graph2d.ForceGraphMethods<graph2d.NodeObject<GraphNode>, graph2d.LinkObject<GraphNode, GraphLink>>;
type GraphRef3D = graph3d.ForceGraphMethods<graph3d.NodeObject<GraphNode>, graph3d.LinkObject<GraphNode, GraphLink>>;

interface GraphContextValue {
  // --- DOM references
  graphRef2D: MutableRefObject<GraphRef2D | undefined>;
  graphRef3D: MutableRefObject<GraphRef3D | undefined>;
  /** Element holding the canvas and the panels floating over it. */
  viewportRef: MutableRefObject<HTMLDivElement | null>;
  /** The toolbar docked under the graph, which can cover the bottom of the canvas. */
  toolbarRef: MutableRefObject<HTMLDivElement | null>;
  // --- data of the graph pass as props
  graphData: LibGraphProps['graphData'];
  setGraphData: Setter<LibGraphProps['graphData']>;
  // --- data of the graph pass as props
  rawObjects: ObjectToParse[];
  setRawObjects: Setter<ObjectToParse[]>;
  rawPositions: OctiGraphPositions;
  setRawPositions: Setter<OctiGraphPositions>;
  // --- graph state (config saved in URL and local storage)
  graphState: GraphState;
  setGraphState: Setter<GraphState>;
  // --- utils data derived from raw data.
  stixCoreObjectTypes: string[];
  /** Relationship types drawn, for the legend. */
  relationshipTypes: string[];
  markingDefinitions: { id: string; definition: string }[];
  creators: { id: string; name: string }[];
  timeRange: GraphTimeRange;
  // --- view state never saved
  isFullscreen: boolean;
  setIsFullscreen: Setter<boolean>;
  // --- misc
  context?: string;
  /** Name of what the graph shows, for the exported image. */
  title?: string;
}

const GraphContext = createContext<GraphContextValue | undefined>(undefined);

interface GraphProviderProps {
  children: ReactNode;
  objects: ObjectToParse[];
  localStorageKey?: string;
  context?: string;
  positions?: OctiGraphPositions;
  title?: string;
}

const GraphStateProvider = ({
  children,
  context,
  localStorageKey,
  objects,
  positions,
  title,
}: GraphProviderProps) => {
  const navigate = useNavigate();
  const location = useLocation();
  const { t_i18n } = useFormatter();
  const { buildGraphData, buildCorrelationData } = useGraphParser();
  const userId = useContext(UserContext).me?.id;

  const graphRef2D = useRef<GraphRef2D | undefined>(undefined);
  const graphRef3D = useRef<GraphRef3D | undefined>(undefined);
  const viewportRef = useRef<HTMLDivElement | null>(null);
  const toolbarRef = useRef<HTMLDivElement | null>(null);

  const DEFAULT_STATE: GraphState = {
    mode3D: false,
    modeTree: null,
    withForces: true,
    selectFreeRectangle: false,
    selectFree: false,
    selectRelationshipMode: null,
    correlationMode: context === 'correlation' ? 'observables' : null,
    showTimeRange: false,
    showLinearProgress: false,
    disabledEntityTypes: [],
    disabledCreators: [],
    disabledMarkings: [],
    selectedLinks: [],
    selectedNodes: [],
    isAddRelationOpen: false,
    isExpandOpen: false,
    layoutMode: null,
    layoutCentreId: null,
    hiddenNodeIds: [],
    collapsedEntityTypes: [],
    disabledRelationshipTypes: [],
    showLegend: readLegendOpen(userId),
    highlightedPath: null,
  };

  const [graphState, setGraphState] = useState<GraphState>(() => {
    // Load initial state for URL and local storage.
    const params = localStorageKey
      ? buildViewParamsFromUrlAndStorage(navigate, location, localStorageKey)
      : {};
    return {
      ...DEFAULT_STATE,
      ...normalizeGraphStateParams(params),
      hiddenNodeIds: localStorageKey ? readHiddenNodeIds(localStorageKey) : [],
    };
  });
  const [isFullscreen, setIsFullscreen] = useState(false);

  useEffect(() => {
    if (localStorageKey) {
      // On state change, update URL and local storage.
      const stateToSave = graphStateToLocalStorage(graphState);
      saveViewParameters(navigate, location, localStorageKey, stateToSave);
    }
  }, [graphState]);

  useEffect(() => {
    if (localStorageKey) writeHiddenNodeIds(localStorageKey, graphState.hiddenNodeIds ?? []);
  }, [graphState.hiddenNodeIds]);

  useEffect(() => {
    writeLegendOpen(userId, graphState.showLegend !== false);
  }, [graphState.showLegend]);

  useEffect(() => {
    // On selection change, reset relationship select mode, and the highlighted path unless both
    // of its ends are still selected.
    setGraphState((oldState) => {
      const path = oldState.highlightedPath;
      const selectedIds = oldState.selectedNodes.map((n) => n.id);
      const keepPath = !!path && path.nodeIds.length > 0
        && selectedIds.includes(path.nodeIds[0])
        && selectedIds.includes(path.nodeIds[path.nodeIds.length - 1]);
      return {
        ...oldState,
        selectRelationshipMode: null,
        highlightedPath: keepPath ? path : null,
      };
    });
  }, [graphState.selectedNodes]);

  const [rawPositions, setRawPositions] = useState(positions ?? {});
  useEffect(() => {
    setRawPositions(positions ?? {});
  }, [positions]);

  const [rawObjects, setRawObjects] = useState(objects ?? []);
  useEffect(() => {
    setRawObjects(objects ?? []);
  }, [objects]);

  const [graphData, setGraphData] = useState<LibGraphProps['graphData']>();
  useEffect(() => {
    const filteredObjects = context === 'correlation' && graphState.correlationMode === 'observables'
      ? objects.filter((o) => (
          o.entity_type === 'Indicator' || o.parent_types.includes('Stix-Cyber-Observable')
        ))
      : objects;
    // Rebuild graph data when input data has changed.
    setGraphData(context === 'correlation'
      ? buildCorrelationData(filteredObjects, rawPositions)
      : buildGraphData(filteredObjects, rawPositions));
  }, [objects, graphState.correlationMode]);

  // Dynamically compute time range values
  const timeRange = useMemo(() => {
    // reset selected range when range is recalculated.
    setGraphState((old) => ({ ...old, selectedTimeRangeInterval: undefined }));
    const links = graphData?.links ?? [];
    const interval = computeTimeRangeInterval(links);
    return {
      interval,
      values: computeTimeRangeValues(interval, links),
    };
  }, [graphData?.links]);

  // Dynamically compute all entity types in graphData.
  const stixCoreObjectTypes = useMemo(() => {
    return (graphData?.nodes ?? [])
      .map(({ relationship_type, entity_type }) => {
        const prefix = relationship_type ? 'relationship_' : 'entity_';
        return { entity_type, label: t_i18n(`${prefix}${entity_type}`) };
      })
      .sort((a, b) => a.label.localeCompare(b.label))
      .map((node) => node.entity_type)
      .filter((v, i, a) => a.indexOf(v) === i);
  }, [graphData?.nodes]);

  // Dynamically compute all relationship types drawn, as the legend counts them: the labelled links
  // and the nested relationships drawn as nodes, not the unlabelled connectors of nested and
  // correlation links.
  const relationshipTypes = useMemo(() => {
    return [...new Set([
      ...(graphData?.links ?? [])
        .filter(({ label }) => !!label)
        .map(({ relationship_type, entity_type }) => relationship_type || entity_type),
      ...(graphData?.nodes ?? []).map(({ relationship_type }) => relationship_type),
    ].filter((type) => !!type))]
      .sort((a, b) => t_i18n(`relationship_${a}`).localeCompare(t_i18n(`relationship_${b}`)));
  }, [graphData?.links, graphData?.nodes]);

  // Dynamically compute all marking definitions in graphData.
  const markingDefinitions = useMemo(() => {
    return [...(graphData?.nodes ?? []), ...(graphData?.links ?? [])]
      .flatMap(({ markedBy }) => markedBy)
      .sort((a, b) => a.definition.localeCompare(b.definition))
      .filter((v, i, a) => a.findIndex((item) => JSON.stringify(item) === JSON.stringify(v)) === i);
  }, [graphData]);

  // Dynamically compute all creator in graphData.
  const creators = useMemo(() => {
    return [...(graphData?.nodes ?? []), ...(graphData?.links ?? [])]
      .flatMap(({ createdBy }) => createdBy)
      .sort((a, b) => a.name.localeCompare(b.name))
      .filter((v, i, a) => a.findIndex((item) => JSON.stringify(item) === JSON.stringify(v)) === i);
  }, [graphData]);

  const value = useMemo<GraphContextValue>(() => ({
    graphRef2D,
    graphRef3D,
    viewportRef,
    toolbarRef,
    graphData,
    stixCoreObjectTypes,
    relationshipTypes,
    markingDefinitions,
    creators,
    graphState,
    timeRange,
    context,
    title,
    isFullscreen,
    setIsFullscreen,
    rawPositions,
    rawObjects,
    setRawObjects,
    setRawPositions,
    setGraphData,
    setGraphState,
  }), [
    graphData,
    graphState,
    rawPositions,
    isFullscreen,
    title,
  ]);

  return (
    <GraphContext.Provider value={value}>
      {children}
    </GraphContext.Provider>
  );
};

/**
 * Kept mounted from one graph to the next (a route change in place), the provider starts over with
 * the view parameters and the hidden entities stored for the new graph: those of the previous graph
 * are neither drawn on it nor stored under its key.
 */
export const GraphProvider = (props: GraphProviderProps) => {
  const { localStorageKey } = props;
  return <GraphStateProvider key={localStorageKey} {...props} />;
};

export const useGraphContext = () => {
  const context = useContext(GraphContext);
  if (!context) throw Error('Hook used outside of GraphProvider');
  return context;
};
