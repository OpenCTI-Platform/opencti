import React, { ReactNode, createContext, useMemo, useState } from 'react';

interface CreateRelationshipContextStateType {
  relationshipTypes?: string[];
  stixCoreObjectTypes?: string[];
  connectionKey?: string;
  reversed?: boolean;
  paginationOptions?: unknown;
  onCreate?: () => void;
}

export interface CreateRelationshipContextType {
  state: CreateRelationshipContextStateType;
  setState: (state: CreateRelationshipContextStateType) => void;
}

const defaultContext: CreateRelationshipContextType = {
  state: {
    relationshipTypes: [],
    stixCoreObjectTypes: [],
    connectionKey: 'Pagination_stixCoreObjects',
    reversed: false,
  },
  setState: () => {},
};

export const CreateRelationshipContext = createContext<CreateRelationshipContextType>(defaultContext);

const CreateRelationshipContextProvider = ({ children }: { children: ReactNode }) => {
  const [relationshipTypes, setRelationshipTypes] = useState<string[]>([]);
  const [stixCoreObjectTypes, setStixCoreObjectTypes] = useState<string[]>([]);
  const [connectionKey, setConnectionKey] = useState<string>('Pagination_stixCoreObjects');
  const [reversed, setReversed] = useState<boolean>(false);
  const [paginationOptions, setPaginationOptions] = useState<unknown>();
  const [onCreate, setOnCreate] = useState<() => void>();
  const state = {
    relationshipTypes,
    stixCoreObjectTypes,
    connectionKey,
    reversed,
    paginationOptions,
    onCreate,
  };
  const setState = ({
    relationshipTypes: updatedRelationshipTypes,
    stixCoreObjectTypes: updatedStixCoreObjectTypes,
    connectionKey: updatedConnectionKey,
    reversed: updatedReversed,
    paginationOptions: updatedPaginationOptions,
    onCreate: updatedOnCreate,
  }: CreateRelationshipContextStateType) => {
    if (updatedRelationshipTypes) setRelationshipTypes(updatedRelationshipTypes);
    if (updatedStixCoreObjectTypes) setStixCoreObjectTypes(updatedStixCoreObjectTypes);
    if (updatedConnectionKey) setConnectionKey(updatedConnectionKey);
    if (updatedReversed) setReversed(updatedReversed);
    if (updatedPaginationOptions) setPaginationOptions(updatedPaginationOptions);
    if (updatedOnCreate) setOnCreate(() => updatedOnCreate); // Dispatching inner function to let context consumer call the onCreate function
  };
  const values = useMemo<CreateRelationshipContextType>(() => ({
    state,
    setState,
  }), [...Object.values(state)]);
  return <CreateRelationshipContext.Provider value={values}>
    {children}
  </CreateRelationshipContext.Provider>;
};

export default CreateRelationshipContextProvider;
