import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React, { createContext, ReactNode, useContext } from 'react';
import { jsonMappers_MappersQuery, jsonMappers_MappersQuery$data } from '@components/data/jsonMapper/__generated__/jsonMappers_MappersQuery.graphql';
import { jsonMappers_SchemaAttributesQuery, jsonMappers_SchemaAttributesQuery$data } from '@components/data/jsonMapper/__generated__/jsonMappers_SchemaAttributesQuery.graphql';

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

export const schemaAttributesQuery = graphql`
  query jsonMappers_SchemaAttributesQuery {
    ...JsonMapperRepresentationAttributesForm_allSchemaAttributes
  }
`;

type JsonMappersContextType = {
  jsonMappers?: jsonMappers_MappersQuery$data,
  schemaAttributes?: jsonMappers_SchemaAttributesQuery$data,
};
const JsonMappersContext = createContext<JsonMappersContextType>({});

interface JsonMappersProviderProps {
  mappersQueryRef: PreloadedQuery<jsonMappers_MappersQuery>
  schemaAttributesQueryRef: PreloadedQuery<jsonMappers_SchemaAttributesQuery>
  children: ReactNode
}
const JsonMappersProvider = ({
  mappersQueryRef,
  schemaAttributesQueryRef,
  children,
}: JsonMappersProviderProps) => {
  const jsonMappers = usePreloadedQuery(mappersQuery, mappersQueryRef);
  const schemaAttributes = usePreloadedQuery(schemaAttributesQuery, schemaAttributesQueryRef);

  return (
    <JsonMappersContext.Provider value={{ jsonMappers, schemaAttributes }}>
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
