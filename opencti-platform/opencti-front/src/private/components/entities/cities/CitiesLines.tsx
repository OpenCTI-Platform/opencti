import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { CityLine, CityLineDummy } from './CityLine';
import { DataColumns } from '../../../../components/list_lines';
import type { UseLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import {
  CitiesLinesPaginationQuery,
  CitiesLinesPaginationQuery$variables,
} from './__generated__/CitiesLinesPaginationQuery.graphql';
import { CitiesLines_data$key } from './__generated__/CitiesLines_data.graphql';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';

const nbOfRowsToLoad = 50;

interface CitiesLinesProps {
  paginationOptions?: CitiesLinesPaginationQuery$variables,
  dataColumns: DataColumns,
  queryRef: PreloadedQuery<CitiesLinesPaginationQuery>,
  setNumberOfElements: UseLocalStorage[2]['handleSetNumberOfElements'],
}

export const citiesLinesQuery = graphql`
  query CitiesLinesPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: CitiesOrdering
    $orderMode: OrderingMode
    $filters: [CitiesFiltering]
  ) {
    ...CitiesLines_data
    @arguments(
      search: $search
      count: $count
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    )
  }
`;

const citiesLinesFragment = graphql`
  fragment CitiesLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int" }
    cursor: { type: "ID" }
    orderBy: { type: "CitiesOrdering" }
    orderMode: { type: "OrderingMode" }
    filters: { type: "[CitiesFiltering]" }
  ) @refetchable(queryName: "CitiesLinesRefetchQuery") {
    cities(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_cities") {
      edges {
        node {
          id
          name
          description
          ...CityLine_node
        }
      }
      pageInfo {
        endCursor
        hasNextPage
        globalCount
      }
    }
  }
`;

const CitiesLines: FunctionComponent<CitiesLinesProps> = ({ setNumberOfElements, dataColumns, queryRef, paginationOptions }) => {
  const {
    data,
    hasMore,
    loadMore,
    isLoadingMore,
  } = usePreloadedPaginationFragment<CitiesLinesPaginationQuery, CitiesLines_data$key>({
    linesQuery: citiesLinesQuery,
    linesFragment: citiesLinesFragment,
    queryRef,
    nodePath: ['cities', 'edges'],
    setNumberOfElements,
  });

  return (
    <ListLinesContent
      initialLoading={!data}
      hasMore={hasMore}
      loadMore={loadMore}
      isLoading={isLoadingMore}
      dataList={data?.cities?.edges ?? []}
      globalCount={data?.cities?.pageInfo?.globalCount ?? nbOfRowsToLoad}
      LineComponent={CityLine}
      DummyLineComponent={CityLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
    />
  );
};

export default CitiesLines;
