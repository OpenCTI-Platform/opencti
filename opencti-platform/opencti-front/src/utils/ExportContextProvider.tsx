import React, { Dispatch, ReactNode, useRef } from 'react';

export interface ExportContextType {
  selectedIds: string[],
  setSelectedIds: Dispatch<string[]>,
}

const defaultContext = {
  selectedIds: [],
  setSelectedIds: () => {},
};

export const ExportContext = React.createContext<ExportContextType>(defaultContext);

const ExportContextProvider = ({ children }: { children: ReactNode }) => {
  const selectedIds = useRef<string[]>([]);

  const setSelectedIds = (value: string[]) => {
    selectedIds.current = value;
  };

  return (
    <ExportContext.Provider value={{ selectedIds: selectedIds.current, setSelectedIds }}>
      {children}
    </ExportContext.Provider>
  );
};

export default ExportContextProvider;
