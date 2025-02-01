import React, { ReactNode, useContext, createContext } from 'react';
import type { DataTableContextProps } from '../dataTableTypes';

const DataTableContext = createContext<DataTableContextProps | undefined>(undefined);

interface DataTableProviderProps {
  children: ReactNode
  initialValue: DataTableContextProps
}

export const DataTableProvider = ({ children, initialValue }: DataTableProviderProps) => {
  return (
    <DataTableContext.Provider value={initialValue}>
      {children}
    </DataTableContext.Provider>
  );
};

export const useDataTableContext = () => {
  const context = useContext(DataTableContext);
  if (!context) throw Error('Hook used outside of DataTableProvider');
  return context;
};
