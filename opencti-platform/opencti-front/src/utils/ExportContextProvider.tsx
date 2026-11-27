import React, { Dispatch, ReactNode, useState } from 'react';

export interface ExportContextType {
  selectedIds: string[];
  setSelectedIds?: Dispatch<string[]>;
  // Number of selected relationships left out of selectedIds, because the export cannot handle them
  excludedRelationshipsCount?: number;
}

const defaultContext = {
  selectedIds: [],
  setSelectedIds: () => {},
  excludedRelationshipsCount: 0,
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
