import React, { createContext, ReactNode, useContext } from 'react';

interface FilterVariableSelectionContextType {
  onVariableSelected: ((variableId: string, variableName: string, filterKeyType: string) => void) | null;
}

const FilterVariableSelectionContext = createContext<FilterVariableSelectionContextType>({
  onVariableSelected: null,
});

export const FilterVariableSelectionProvider = ({
  children,
  onVariableSelected,
}: {
  children: ReactNode;
  onVariableSelected: (variableId: string, variableName: string, filterKeyType: string) => void;
}) => (
  <FilterVariableSelectionContext.Provider value={{ onVariableSelected }}>
    {children}
  </FilterVariableSelectionContext.Provider>
);

export const useFilterVariableSelection = () => useContext(FilterVariableSelectionContext);
