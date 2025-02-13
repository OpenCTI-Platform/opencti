import React, { ReactNode, useContext, createContext, useState, useEffect, useMemo, Dispatch, SetStateAction } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { buildViewParamsFromUrlAndStorage, saveViewParameters } from '../../ListParameters';
import type { GraphNode, GraphLink } from '../graph.types';

// Stuff kept in URL and local storage.
export interface GraphState {
  mode3D: boolean
  modeTree: 'td' | 'lr' | null
  withForces: boolean
  selectFreeRectangle: boolean
  selectFree: boolean
  selectRelationshipMode: 'children' | 'parent' | 'deselect' | null
  showTimeRange: boolean
  zoom?: {
    k: number
    x: number
    y: number
  }
}

// API available when calling hook useGraphContext().
interface GraphContextProps {
  graphState: GraphState
  setGraphStateProp: <K extends keyof GraphState>(key: K, value: GraphState[K]) => void
  selectedNodes: GraphNode[]
  setSelectedNodes: Dispatch<SetStateAction<GraphNode[]>>
  addSelectedNode: (node: GraphNode) => void
  removeSelectedNode: (node: GraphNode) => void
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
}

export const GraphProvider = ({
  children,
  defaultState,
  localStorageKey,
}: GraphProviderProps) => {
  const navigate = useNavigate();
  const location = useLocation();

  const [selectedNodes, setSelectedNodes] = useState<GraphNode[]>([]);
  const [selectedLinks, setSelectedLinks] = useState<GraphLink[]>([]);

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

  const addSelectedLink = (link: GraphLink) => {
    setSelectedLinks((old) => [...old, link]);
  };

  const removeSelectedLink = (link: GraphLink) => {
    setSelectedLinks((old) => old.filter((l) => l.id !== link.id));
  };

  const addSelectedNode = (node: GraphNode) => {
    setSelectedNodes((old) => [...old, node]);
  };

  const removeSelectedNode = (node: GraphNode) => {
    setSelectedNodes((old) => old.filter((n) => n.id !== node.id));
  };

  const value = useMemo<GraphContextProps>(() => ({
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
