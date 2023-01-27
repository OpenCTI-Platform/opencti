import React, { Dispatch, ReactNode, useState } from 'react';

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
  const [selectedIds, setSelectedIds] = useState<string[]>([]);

  return (
    <ExportContext.Provider value={{ selectedIds, setSelectedIds }}>
      {children}
    </ExportContext.Provider>
  );
};

export default ExportContextProvider;
