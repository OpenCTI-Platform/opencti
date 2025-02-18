import React, { ReactNode, useContext, createContext, useState, useEffect, useMemo, Dispatch, SetStateAction, MutableRefObject, useRef } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import * as graph2d from 'react-force-graph-2d';
import * as graph3d from 'react-force-graph-3d';
import { buildViewParamsFromUrlAndStorage, saveViewParameters } from '../../ListParameters';
import { GraphNode, GraphLink, LibGraphProps } from '../graph.types';
import { useFormatter } from '../../../components/i18n';

type GraphRef2D = graph2d.ForceGraphMethods<graph2d.NodeObject<GraphNode>, graph2d.LinkObject<GraphNode, GraphLink>>;
type GraphRef3D = graph3d.ForceGraphMethods<graph3d.NodeObject<GraphNode>, graph3d.LinkObject<GraphNode, GraphLink>>;

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

// API available when calling hook useGraphContext().
interface GraphContextProps {
  graphData: LibGraphProps['graphData']
  addNode: (node: GraphNode) => void
  removeNode: (id: string) => void
  addLink: (link: GraphLink) => void
  removeLink: (id: string) => void
  stixCoreObjectTypes: string[]
  markingDefinitions: { id: string, definition: string }[]
  creators: { id: string, name: string }[]
  // --- DOM references
  graphRef2D: MutableRefObject<GraphRef2D | undefined>
  graphRef3D: MutableRefObject<GraphRef3D | undefined>
  // --- graph state (config saved in URL and local storage)
  graphState: GraphState
  setGraphStateProp: <K extends keyof GraphState>(key: K, value: GraphState[K]) => void
  // --- selected nodes
  selectedNodes: GraphNode[]
  setSelectedNodes: Dispatch<SetStateAction<GraphNode[]>>
  addSelectedNode: (node: GraphNode) => void
  removeSelectedNode: (node: GraphNode) => void
  // --- selected links
  selectedLinks: GraphLink[]
  setSelectedLinks: Dispatch<SetStateAction<GraphLink[]>>
  addSelectedLink: (link: GraphLink) => void
  removeSelectedLink: (link: GraphLink) => void
}

const GraphContext = createContext<GraphContextProps | undefined>(undefined);

interface GraphProviderProps {
  children: ReactNode
  defaultState: GraphState
  localStorageKey: string
  data: LibGraphProps['graphData']
}

export const GraphProvider = ({
  children,
  defaultState,
  localStorageKey,
  data,
}: GraphProviderProps) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const location = useLocation();

  const graphRef2D = useRef<GraphRef2D | undefined>();
  const graphRef3D = useRef<GraphRef3D | undefined>();

  const [graphData, setGraphData] = useState(data);

  const addNode = (node: GraphNode) => {
    setGraphData((oldData) => {
      const withoutExisting = (oldData?.nodes ?? []).filter((n) => n.id !== node.id);
      return {
        nodes: [...withoutExisting, node],
        links: oldData?.links ?? [],
      };
    });
  };

  const removeNode = (id: string) => {
    setGraphData((oldData) => {
      return {
        nodes: (oldData?.nodes ?? []).filter((node) => node.id !== id),
        links: oldData?.links ?? [],
      };
    });
  };

  const addLink = (link: GraphLink) => {
    setGraphData((oldData) => {
      const withoutExisting = (oldData?.links ?? []).filter((l) => l.id !== link.id);
      return {
        links: [...withoutExisting, link],
        nodes: oldData?.nodes ?? [],
      };
    });
  };

  const removeLink = (id: string) => {
    setGraphData((oldData) => {
      return {
        links: (oldData?.links ?? []).filter((link) => link.id !== id),
        nodes: oldData?.nodes ?? [],
      };
    });
  };

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
    return { ...defaultState, ...params };
  });

  useEffect(() => {
    // On state change, update URL and local storage.
    saveViewParameters(navigate, location, localStorageKey, graphState);
  }, [graphState]);

  /**
   * Helper function to easily modify one property in the state.
   *
   * @param key Name of the property to change.
   * @param value New value for the property.
   */
  const setGraphStateProp = <K extends keyof GraphState>(key: K, value: GraphState[K]) => {
    setGraphState((oldState) => {
      return { ...oldState, [key]: value };
    });
  };

  const [selectedNodes, setSelectedNodes] = useState<GraphNode[]>([]);
  const [selectedLinks, setSelectedLinks] = useState<GraphLink[]>([]);

  const addSelectedLink = (link: GraphLink) => {
    const existing = selectedLinks.find((l) => l.id === link.id);
    if (!existing) setSelectedLinks((old) => [...old, link]);
  };

  const removeSelectedLink = (link: GraphLink) => {
    setSelectedLinks((old) => old.filter((l) => l.id !== link.id));
  };

  const addSelectedNode = (node: GraphNode) => {
    const existing = selectedNodes.find((n) => n.id === node.id);
    if (!existing) setSelectedNodes((old) => [...old, node]);
  };

  const removeSelectedNode = (node: GraphNode) => {
    setSelectedNodes((old) => old.filter((n) => n.id !== node.id));
  };

  const value = useMemo<GraphContextProps>(() => ({
    graphData,
    addNode,
    removeNode,
    addLink,
    removeLink,
    stixCoreObjectTypes,
    markingDefinitions,
    creators,
    graphRef2D,
    graphRef3D,
    graphState,
    setGraphStateProp,
    selectedLinks,
    setSelectedLinks,
    addSelectedLink,
    removeSelectedLink,
    selectedNodes,
    setSelectedNodes,
    addSelectedNode,
    removeSelectedNode,
  }), [graphState, selectedLinks, selectedNodes]);

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
