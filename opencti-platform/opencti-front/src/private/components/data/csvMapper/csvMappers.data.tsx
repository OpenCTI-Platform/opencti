import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React, { createContext, ReactNode, useContext } from 'react';
import { csvMappers_MappersQuery, csvMappers_MappersQuery$data } from '@components/data/csvMapper/__generated__/csvMappers_MappersQuery.graphql';
import { csvMappers_SchemaAttributesQuery, csvMappers_SchemaAttributesQuery$data } from '@components/data/csvMapper/__generated__/csvMappers_SchemaAttributesQuery.graphql';

export const mappersQuery = graphql`
  query csvMappers_MappersQuery(
    $count: Int
    $orderBy: CsvMapperOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
    $search: String
  ) {
    ...CsvMapperLines_csvMapper
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
  query csvMappers_SchemaAttributesQuery {
    ...CsvMapperRepresentationAttributesForm_allSchemaAttributes
  }
`;

type CsvMappersContextType = {
  csvMappers?: csvMappers_MappersQuery$data,
  schemaAttributes?: csvMappers_SchemaAttributesQuery$data,
};
const CsvMappersContext = createContext<CsvMappersContextType>({});

interface CsvMappersProviderProps {
  mappersQueryRef: PreloadedQuery<csvMappers_MappersQuery>
  schemaAttributesQueryRef: PreloadedQuery<csvMappers_SchemaAttributesQuery>
  children: ReactNode
}
const CsvMappersProvider = ({
  mappersQueryRef,
  schemaAttributesQueryRef,
  children,
}: CsvMappersProviderProps) => {
  const csvMappers = usePreloadedQuery(mappersQuery, mappersQueryRef);
  const schemaAttributes = usePreloadedQuery(schemaAttributesQuery, schemaAttributesQueryRef);

  return (
    <CsvMappersContext.Provider value={{ csvMappers, schemaAttributes }}>
      {children}
    </CsvMappersContext.Provider>
  );
};

export const useCsvMappersData = () => {
  const context = useContext(CsvMappersContext);
  if (!context) {
    throw new Error(
      'useCsvMappersData must be used within a CsvMappersProvider',
    );
  }
  return context;
};

export default CsvMappersProvider;
