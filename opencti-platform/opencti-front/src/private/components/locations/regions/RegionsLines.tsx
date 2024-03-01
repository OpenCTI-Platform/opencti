import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import { RegionLineComponent, RegionLineDummy } from './RegionLine';
import { RegionsLinesPaginationQuery, RegionsLinesPaginationQuery$variables } from './__generated__/RegionsLinesPaginationQuery.graphql';
import { DataColumns } from '../../../../components/list_lines';
import { UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { RegionsLines_data$key } from './__generated__/RegionsLines_data.graphql';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';

const nbOfRowsToLoad = 50;

interface RegionsLinesProps {
  queryRef: PreloadedQuery<RegionsLinesPaginationQuery>;
  dataColumns: DataColumns;
  paginationOptions?: RegionsLinesPaginationQuery$variables;
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
}

export const regionsLinesQuery = graphql`
  query RegionsLinesPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: RegionsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...RegionsLines_data
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

const regionsLinesFragment = graphql`
  fragment RegionsLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "RegionsOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "RegionsLinesRefetchQuery") {
    regions(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_regions") {
      edges {
        node {
          id
          name
          description
          ...RegionLine_node
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

const RegionsLinesComponent: FunctionComponent<RegionsLinesProps> = ({
  setNumberOfElements,
  queryRef,
  dataColumns,
  paginationOptions,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  RegionsLinesPaginationQuery,
  RegionsLines_data$key
  >({
    linesQuery: regionsLinesQuery,
    linesFragment: regionsLinesFragment,
    queryRef,
    nodePath: ['regions', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });
  return (
    <ListLinesContent
      initialLoading={!data}
      isLoading={isLoadingMore}
      loadMore={loadMore}
      hasMore={hasMore}
      dataList={data?.regions?.edges ?? []}
      globalCount={data?.regions?.pageInfo?.globalCount ?? nbOfRowsToLoad}
      LineComponent={RegionLineComponent}
      DummyLineComponent={RegionLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
    />
  );
};

export default RegionsLinesComponent;
