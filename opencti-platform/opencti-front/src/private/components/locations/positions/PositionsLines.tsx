import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { PositionLine, PositionLineDummy } from './PositionLine';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { PositionsLinesPaginationQuery, PositionsLinesPaginationQuery$variables } from './__generated__/PositionsLinesPaginationQuery.graphql';
import { PositionsLines_data$key } from './__generated__/PositionsLines_data.graphql';
import { DataColumns } from '../../../../components/list_lines';
import { UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';

const nbOfRowsToLoad = 50;

interface PositionsLinesProps {
  queryRef: PreloadedQuery<PositionsLinesPaginationQuery>;
  dataColumns: DataColumns;
  paginationOptions?: PositionsLinesPaginationQuery$variables;
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
}

export const positionsLinesQuery = graphql`
  query PositionsLinesPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: PositionsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...PositionsLines_data
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

const positionsLinesFragment = graphql`
  fragment PositionsLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "PositionsOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "PositionsLinesRefetchQuery") {
    positions(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_positions") {
      edges {
        node {
          id
          name
          description
          ...PositionLine_node
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

const PositionsLines: FunctionComponent<PositionsLinesProps> = ({
  setNumberOfElements,
  queryRef,
  dataColumns,
  paginationOptions,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  PositionsLinesPaginationQuery,
  PositionsLines_data$key
  >({
    linesQuery: positionsLinesQuery,
    linesFragment: positionsLinesFragment,
    queryRef,
    nodePath: ['positions', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });
  return (
    <ListLinesContent
      initialLoading={!data}
      isLoading={isLoadingMore}
      loadMore={loadMore}
      hasMore={hasMore}
      dataList={data?.positions?.edges ?? []}
      globalCount={data?.positions?.pageInfo?.globalCount ?? nbOfRowsToLoad}
      LineComponent={PositionLine}
      DummyLineComponent={PositionLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
    />
  );
};

export default PositionsLines;
