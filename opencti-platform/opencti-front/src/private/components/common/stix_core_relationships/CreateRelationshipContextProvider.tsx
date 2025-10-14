import React, { ReactNode, createContext, useMemo, useState, useContext, useEffect } from 'react';

interface CreateRelationshipContextStateType {
  relationshipTypes?: string[];
  stixCoreObjectTypes?: string[];
  connectionKey?: string;
  reversed?: boolean;
  handleReverseRelation?: () => void;
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
    stixCoreObjectTypes: ['Stix-Domain-Object', 'Stix-Cyber-Observable'],
    connectionKey: 'Pagination_stixCoreObjects',
    reversed: false,
  },
  setState: () => {},
};

export const CreateRelationshipContext = createContext<CreateRelationshipContextType>(defaultContext);

const CreateRelationshipContextProvider = ({ children }: { children: ReactNode }) => {
  const [relationshipTypes, setRelationshipTypes] = useState<string[]>([]);
  const [stixCoreObjectTypes, setStixCoreObjectTypes] = useState<string[]>([
    'Stix-Domain-Object',
    'Stix-Cyber-Observable',
  ]);
  const [connectionKey, setConnectionKey] = useState<string>('Pagination_stixCoreObjects');
  const [reversed, setReversed] = useState<boolean>(false);
  const [handleReverseRelation, setHandleReverseRelation] = useState<() => void>();
  const [paginationOptions, setPaginationOptions] = useState<unknown>();
  const [onCreate, setOnCreate] = useState<() => void | undefined>();
  const state = {
    relationshipTypes,
    stixCoreObjectTypes,
    connectionKey,
    reversed,
    handleReverseRelation,
    paginationOptions,
    onCreate,
  };
  const setState = ({
    relationshipTypes: updatedRelationshipTypes,
    stixCoreObjectTypes: updatedStixCoreObjectTypes,
    connectionKey: updatedConnectionKey,
    reversed: updatedReversed,
    handleReverseRelation: updatedHandleReverseRelation,
    paginationOptions: updatedPaginationOptions,
    onCreate: updatedOnCreate,
  }: CreateRelationshipContextStateType) => {
    if (updatedRelationshipTypes) setRelationshipTypes(updatedRelationshipTypes);
    if (updatedStixCoreObjectTypes) setStixCoreObjectTypes(updatedStixCoreObjectTypes);
    if (updatedConnectionKey) setConnectionKey(updatedConnectionKey);
    if (updatedReversed !== undefined) setReversed(updatedReversed);
    setHandleReverseRelation(() => updatedHandleReverseRelation);
    if (paginationOptions !== updatedPaginationOptions) setPaginationOptions(updatedPaginationOptions);
    if (onCreate !== updatedOnCreate) setOnCreate(() => updatedOnCreate); // Dispatching inner function to let context consumer call the onCreate function
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

export const useInitCreateRelationshipContext = (state: CreateRelationshipContextStateType = {
  stixCoreObjectTypes: ['Stix-Core-Object'],
  relationshipTypes: [],
  onCreate: undefined,
  paginationOptions: undefined,
  reversed: false,
}) => {
  const { setState } = useContext(CreateRelationshipContext);
  useEffect(() => {
    setState(state);
  }, []);
};
