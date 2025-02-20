import React, { ReactNode, useContext, createContext, useState, useEffect, useMemo, Dispatch, SetStateAction, MutableRefObject, useRef } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import * as graph2d from 'react-force-graph-2d';
import * as graph3d from 'react-force-graph-3d';
import { buildViewParamsFromUrlAndStorage, saveViewParameters } from '../ListParameters';
import { GraphNode, GraphLink, LibGraphProps, GraphState, OctiGraphPositions } from './graph.types';
import { useFormatter } from '../../components/i18n';
import useGraphParser, { ObjectToParse } from './utils/useGraphParser';
import { computeTimeRangeInterval, computeTimeRangeValues, GraphTimeRange } from './utils/graphTimeRange';

type Setter<T> = Dispatch<SetStateAction<T>>;

type GraphRef2D = graph2d.ForceGraphMethods<graph2d.NodeObject<GraphNode>, graph2d.LinkObject<GraphNode, GraphLink>>;
type GraphRef3D = graph3d.ForceGraphMethods<graph3d.NodeObject<GraphNode>, graph3d.LinkObject<GraphNode, GraphLink>>;

interface GraphContextValue {
  // --- DOM references
  graphRef2D: MutableRefObject<GraphRef2D | undefined>
  graphRef3D: MutableRefObject<GraphRef3D | undefined>
  // --- data of the graph
  graphData: LibGraphProps['graphData']
  setGraphData: Setter<LibGraphProps['graphData']>
  // --- graph state (config saved in URL and local storage)
  graphState: GraphState
  setGraphState: Setter<GraphState>
  // --- selected nodes
  selectedNodes: GraphNode[]
  setSelectedNodes: Setter<GraphNode[]>
  // --- selected links
  selectedLinks: GraphLink[]
  setSelectedLinks: Setter<GraphLink[]>
  // --- utils data derived from input data.
  stixCoreObjectTypes: string[]
  markingDefinitions: { id: string, definition: string }[]
  creators: { id: string, name: string }[]
  positions: OctiGraphPositions
  timeRange: GraphTimeRange
  // --- misc
  isAddRelationOpen: boolean
  setIsAddRelationOpen: Setter<boolean>
}

const GraphContext = createContext<GraphContextValue | undefined>(undefined);

const DEFAULT_STATE: GraphState = {
  mode3D: false,
  modeTree: null,
  withForces: true,
  selectFreeRectangle: false,
  selectFree: false,
  selectRelationshipMode: null,
  showTimeRange: false,
  disabledEntityTypes: [],
  disabledCreators: [],
  disabledMarkings: [],
};

interface GraphProviderProps {
  children: ReactNode
  localStorageKey: string
  data: {
    objects: ObjectToParse[]
    positions: OctiGraphPositions
  }
}

export const GraphProvider = ({
  children,
  localStorageKey,
  data,
}: GraphProviderProps) => {
  const navigate = useNavigate();
  const location = useLocation();
  const { t_i18n } = useFormatter();
  const { buildGraphData } = useGraphParser();

  const graphRef2D = useRef<GraphRef2D | undefined>();
  const graphRef3D = useRef<GraphRef3D | undefined>();

  const [graphData, setGraphData] = useState<LibGraphProps['graphData']>();
  useEffect(() => {
    // Rebuild graph data when input data has changed.
    setGraphData(buildGraphData(data.objects, data.positions));
  }, [data]);

  // Dynamically compute time range values
  const timeRange = useMemo(() => {
    const interval = computeTimeRangeInterval(data.objects);
    return {
      interval,
      values: computeTimeRangeValues(interval, data.objects),
    };
  }, [data.objects]);

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
  }, [graphData]);

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

  const [graphState, setGraphState] = useState<GraphState>(() => {
    // Load initial state for URL and local storage.
    const params = buildViewParamsFromUrlAndStorage(navigate, location, localStorageKey);
    return { ...DEFAULT_STATE, ...params };
  });

  useEffect(() => {
    // On state change, update URL and local storage.
    saveViewParameters(navigate, location, localStorageKey, graphState);
  }, [graphState]);

  const [selectedNodes, setSelectedNodes] = useState<GraphNode[]>([]);
  const [selectedLinks, setSelectedLinks] = useState<GraphLink[]>([]);

  useEffect(() => {
    // On selection change, reset relationship select mode.
    setGraphState((oldState) => ({
      ...oldState,
      selectRelationshipMode: null,
    }));
  }, [selectedNodes]);

  // Put inside context because the dialog to create relationship can be
  // opened by other source than click in toolbar (cf <RelationSelection />).
  const [isAddRelationOpen, setIsAddRelationOpen] = useState(false);

  const value = useMemo<GraphContextValue>(() => ({
    graphRef2D,
    graphRef3D,
    graphData,
    stixCoreObjectTypes,
    markingDefinitions,
    creators,
    graphState,
    selectedLinks,
    selectedNodes,
    isAddRelationOpen,
    timeRange,
    positions: data.positions,
    setGraphData,
    setGraphState,
    setSelectedLinks,
    setSelectedNodes,
    setIsAddRelationOpen,
  }), [
    graphData,
    graphState,
    selectedLinks,
    selectedNodes,
    data,
    isAddRelationOpen,
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
