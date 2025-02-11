import React, { ReactNode, useContext, createContext, useState, Dispatch } from 'react';
import type { GraphState } from '../graph.types';

type StateGet<T> = T;
type StateSet<T> = Dispatch<React.SetStateAction<T>>;

interface GraphContextProps {
  graphState: StateGet<GraphState>
  setGraphState: StateSet<GraphState>
  setGraphProp: (key: keyof GraphState, value: unknown) => void
}

const GraphContext = createContext<GraphContextProps | undefined>(undefined);

interface GraphProviderProps {
  children: ReactNode
  defaultState: GraphState
}

export const GraphProvider = ({ children, defaultState }: GraphProviderProps) => {
  const [graphState, setGraphState] = useState<GraphState>(defaultState);

  const setGraphProp = (key: keyof GraphState, value: unknown) => {
    setGraphState((oldState) => {
      return { ...oldState, [key]: value };
    });
  };

  return (
    <GraphContext.Provider value={{ graphState, setGraphState, setGraphProp }}>
      {children}
    </GraphContext.Provider>
  );
};

export const useGraphContext = () => {
  const context = useContext(GraphContext);
  if (!context) throw Error('Hook used outside of GraphProvider');
  return context;
};
