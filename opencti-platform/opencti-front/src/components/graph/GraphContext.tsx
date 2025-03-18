import React, { ReactNode, useContext, createContext, useState, useEffect, useMemo, Dispatch, SetStateAction, MutableRefObject, useRef } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import * as graph2d from 'react-force-graph-2d';
import * as graph3d from 'react-force-graph-3d';
import { buildViewParamsFromUrlAndStorage, saveViewParameters } from '../../utils/ListParameters';
import { GraphNode, GraphLink, LibGraphProps, GraphState, OctiGraphPositions } from './graph.types';
import { useFormatter } from '../i18n';
import useGraphParser, { ObjectToParse } from './utils/useGraphParser';
import { computeTimeRangeInterval, computeTimeRangeValues, GraphTimeRange } from './utils/graphTimeRange';
import { graphStateToLocalStorage } from './utils/graphUtils';

type Setter<T> = Dispatch<SetStateAction<T>>;

type GraphRef2D = graph2d.ForceGraphMethods<graph2d.NodeObject<GraphNode>, graph2d.LinkObject<GraphNode, GraphLink>>;
type GraphRef3D = graph3d.ForceGraphMethods<graph3d.NodeObject<GraphNode>, graph3d.LinkObject<GraphNode, GraphLink>>;

interface GraphContextValue {
  // --- DOM references
  graphRef2D: MutableRefObject<GraphRef2D | undefined>
  graphRef3D: MutableRefObject<GraphRef3D | undefined>
  // --- data of the graph pass as props
  graphData: LibGraphProps['graphData']
  setGraphData: Setter<LibGraphProps['graphData']>
  // --- data of the graph pass as props
  rawObjects: ObjectToParse[]
  rawPositions: OctiGraphPositions
  setRawPositions: Setter<OctiGraphPositions>
  // --- graph state (config saved in URL and local storage)
  graphState: GraphState
  setGraphState: Setter<GraphState>
  // --- utils data derived from raw data.
  stixCoreObjectTypes: string[]
  markingDefinitions: { id: string, definition: string }[]
  creators: { id: string, name: string }[]
  timeRange: GraphTimeRange
  // --- misc
  context?: string
}

const GraphContext = createContext<GraphContextValue | undefined>(undefined);

interface GraphProviderProps {
  children: ReactNode
  localStorageKey: string
  context?: string
  objects: ObjectToParse[]
  positions: OctiGraphPositions
}

export const GraphProvider = ({
  children,
  context,
  localStorageKey,
  objects,
  positions,
}: GraphProviderProps) => {
  const navigate = useNavigate();
  const location = useLocation();
  const { t_i18n } = useFormatter();
  const { buildGraphData, buildCorrelationData } = useGraphParser();

  const graphRef2D = useRef<GraphRef2D | undefined>();
  const graphRef3D = useRef<GraphRef3D | undefined>();

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
  };

  const [graphState, setGraphState] = useState<GraphState>(() => {
    // Load initial state for URL and local storage.
    const params = buildViewParamsFromUrlAndStorage(navigate, location, localStorageKey);
    return { ...DEFAULT_STATE, ...params };
  });

  useEffect(() => {
    // On state change, update URL and local storage.
    const stateToSave = graphStateToLocalStorage(graphState);
    saveViewParameters(navigate, location, localStorageKey, stateToSave);
  }, [graphState]);

  useEffect(() => {
    // On selection change, reset relationship select mode.
    setGraphState((oldState) => ({
      ...oldState,
      selectRelationshipMode: null,
    }));
  }, [graphState.selectedNodes]);

  const [rawPositions, setRawPositions] = useState(positions);
  useEffect(() => {
    setRawPositions(positions);
  }, [positions]);

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
      .filter((v, i, a) => a.indexOf(v) === i)
      .filter((v) => !['Note', 'Opinion'].includes(v));
  }, [graphData?.nodes]);

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
    graphData,
    stixCoreObjectTypes,
    markingDefinitions,
    creators,
    graphState,
    timeRange,
    context,
    rawPositions,
    rawObjects: objects,
    setRawPositions,
    setGraphData,
    setGraphState,
  }), [
    graphData,
    graphState,
    rawPositions,
  ]);

  return (
    <GraphContext.Provider value={value}>
      {children}
    </GraphContext.Provider>
  );
};

export const useGraphContext = () => {
  const context = useContext(GraphContext);
  if (!context) throw Error('Hook used outside of GraphProvider');
  return context;
};
