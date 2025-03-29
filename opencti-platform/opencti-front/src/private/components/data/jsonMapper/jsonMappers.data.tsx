import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React, { createContext, ReactNode, useContext } from 'react';
import { jsonMappers_MappersQuery, jsonMappers_MappersQuery$data } from './__generated__/jsonMappers_MappersQuery.graphql';

export const mappersQuery = graphql`
  query jsonMappers_MappersQuery(
    $count: Int
    $orderBy: JsonMapperOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
    $search: String
  ) {
    ...JsonMapperLines_jsonMapper
    @arguments(
      count: $count
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
      search: $search
    )
  }
`;

type JsonMappersContextType = {
  jsonMappers?: jsonMappers_MappersQuery$data,
};
const JsonMappersContext = createContext<JsonMappersContextType>({});

interface JsonMappersProviderProps {
  mappersQueryRef: PreloadedQuery<jsonMappers_MappersQuery>
  children: ReactNode
}
const JsonMappersProvider = ({
  mappersQueryRef,
  children,
}: JsonMappersProviderProps) => {
  const jsonMappers = usePreloadedQuery(mappersQuery, mappersQueryRef);
  return (
    <JsonMappersContext.Provider value={{ jsonMappers }}>
      {children}
    </JsonMappersContext.Provider>
  );
};

export const useJsonMappersData = () => {
  const context = useContext(JsonMappersContext);
  if (!context) {
    throw new Error(
      'useJsonMappersData must be used within a JsonMappersProvider',
    );
  }
  return context;
};

export default JsonMappersProvider;
