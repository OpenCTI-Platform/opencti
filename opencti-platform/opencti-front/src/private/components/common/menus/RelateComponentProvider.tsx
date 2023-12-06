import React, { Dispatch, ReactNode, createContext, useState } from 'react';
import { Filter, FilterGroup, FilterValue, emptyFilterGroup } from 'src/utils/filters/filtersUtils';
import { handleFilterHelpers } from 'src/utils/hooks/useLocalStorage';

export interface RelateComponentContextType {
  relationshipTypes: string[];
  setRelationshipTypes: Dispatch<string[]>;
  stixCoreObjectTypes: string[];
  setStixCoreObjectTypes: Dispatch<string[]>;
  filters: FilterGroup;
  setFilters: Dispatch<FilterGroup>;
  helpers: handleFilterHelpers;
  setHelpers: Dispatch<handleFilterHelpers>;
}

const defaultHelpers: handleFilterHelpers = {
  handleSwitchGlobalMode(): void {
    throw new Error('Function not implemented.');
  },
  handleSwitchLocalMode(_filter: Filter): void {
    throw new Error('Function not implemented.');
  },
  handleRemoveRepresentationFilter(_id: string, _valueId: string): void {
    throw new Error('Function not implemented.');
  },
  handleRemoveFilterById(_id: string): void {
    throw new Error('Function not implemented.');
  },
  handleChangeOperatorFilters(_id: string, _op: string): void {
    throw new Error('Function not implemented.');
  },
  handleAddSingleValueFilter(_id: string, _valueId?: string | undefined): void {
    throw new Error('Function not implemented.');
  },
  handleAddRepresentationFilter(_id: string, _valueId: string): void {
    throw new Error('Function not implemented.');
  },
  handleAddFilterWithEmptyValue(_filter: Filter): void {
    throw new Error('Function not implemented.');
  },
  handleClearAllFilters(_filters?: Filter[] | undefined): void {
    throw new Error('Function not implemented.');
  },
  getLatestAddFilterId(): string | undefined {
    throw new Error('Function not implemented.');
  },
  handleChangeRepresentationFilter(_id: string, _oldValue: FilterValue, _newValue: FilterValue): void {
    throw new Error('Function not implemented.');
  },
};

const defaultContext: RelateComponentContextType = {
  relationshipTypes: [],
  setRelationshipTypes: () => {},
  stixCoreObjectTypes: [],
  setStixCoreObjectTypes: () => {},
  filters: emptyFilterGroup,
  setFilters: () => {},
  helpers: defaultHelpers,
  setHelpers: () => {},
};

export const RelateComponentContext = createContext<RelateComponentContextType>(defaultContext);

const RelateComponentContextProvider = ({ children }: { children: ReactNode }) => {
  const [relationshipTypes, setRelationshipTypes] = useState<string[]>([]);
  const [stixCoreObjectTypes, setStixCoreObjectTypes] = useState<string[]>([]);
  const [filters, setFilters] = useState<FilterGroup>(emptyFilterGroup);
  const [helpers, setHelpers] = useState<handleFilterHelpers>(defaultHelpers);
  return <RelateComponentContext.Provider value={{
    relationshipTypes,
    setRelationshipTypes,
    stixCoreObjectTypes,
    setStixCoreObjectTypes,
    filters,
    setFilters,
    helpers,
    setHelpers,
  }}
         >
    {children}
  </RelateComponentContext.Provider>;
};

export default RelateComponentContextProvider;
