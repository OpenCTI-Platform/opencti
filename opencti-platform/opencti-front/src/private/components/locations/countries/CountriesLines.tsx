import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import { DataColumns } from '../../../../components/list_lines';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { CountryLineComponent, CountryLineDummy } from './CountryLine';
import { CountriesLines_data$key } from './__generated__/CountriesLines_data.graphql';
import { CountriesLinesPaginationQuery, CountriesLinesPaginationQuery$variables } from './__generated__/CountriesLinesPaginationQuery.graphql';
import { UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';

const nbOfRowsToLoad = 50;

interface CountriesLinesProps {
  queryRef: PreloadedQuery<CountriesLinesPaginationQuery>;
  dataColumns: DataColumns;
  paginationOptions?: CountriesLinesPaginationQuery$variables;
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
}

export const countriesLinesQuery = graphql`
  query CountriesLinesPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: CountriesOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...CountriesLines_data
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

const countriesLinesFragment = graphql`
  fragment CountriesLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "CountriesOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "CountriesLinesRefetchQuery") {
    countries(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_countries") {
      edges {
        node {
          id
          name
          description
          ...CountryLine_node
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

const CountriesLines: FunctionComponent<CountriesLinesProps> = ({
  setNumberOfElements,
  queryRef,
  dataColumns,
  paginationOptions,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  CountriesLinesPaginationQuery,
  CountriesLines_data$key
  >({
    linesQuery: countriesLinesQuery,
    linesFragment: countriesLinesFragment,
    queryRef,
    nodePath: ['countries', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });
  return (
    <ListLinesContent
      initialLoading={!data}
      isLoading={isLoadingMore}
      loadMore={loadMore}
      hasMore={hasMore}
      dataList={data?.countries?.edges ?? []}
      globalCount={data?.countries?.pageInfo?.globalCount ?? nbOfRowsToLoad}
      LineComponent={CountryLineComponent}
      DummyLineComponent={CountryLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
    />
  );
};

export default CountriesLines;
