import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import { DataComponentsLines_data$key } from './__generated__/DataComponentsLines_data.graphql';
import { DataColumns } from '../../../../components/list_lines';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { DataComponentsLinesPaginationQuery, DataComponentsLinesPaginationQuery$variables } from './__generated__/DataComponentsLinesPaginationQuery.graphql';
import DataComponentLineDummy from './DataComponentLineDummy';
import DataComponentLine from './DataComponentLine';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { HandleAddFilter, UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';

const nbOfRowsToLoad = 50;

interface DataComponentsLinesProps {
  dataColumns: DataColumns;
  onLabelClick: HandleAddFilter;
  paginationOptions: DataComponentsLinesPaginationQuery$variables;
  queryRef: PreloadedQuery<DataComponentsLinesPaginationQuery>;
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
}

export const dataComponentsLinesQuery = graphql`
  query DataComponentsLinesPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: DataComponentsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...DataComponentsLines_data
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

const dataComponentsLinesFragment = graphql`
  fragment DataComponentsLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "DataComponentsOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "DataComponentsLinesRefetchQuery") {
    dataComponents(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_dataComponents") {
      edges {
        node {
          ...DataComponentLine_node
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

const DataComponentsLines: FunctionComponent<DataComponentsLinesProps> = ({
  dataColumns,
  onLabelClick,
  paginationOptions,
  queryRef,
  setNumberOfElements,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  DataComponentsLinesPaginationQuery,
  DataComponentsLines_data$key
  >({
    linesQuery: dataComponentsLinesQuery,
    linesFragment: dataComponentsLinesFragment,
    queryRef,
    nodePath: ['dataComponents', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });

  return (
    <ListLinesContent
      hasMore={hasMore}
      initialLoading={!data}
      isLoading={isLoadingMore}
      loadMore={loadMore}
      dataList={data?.dataComponents?.edges ?? []}
      globalCount={
        data?.dataComponents?.pageInfo?.globalCount ?? nbOfRowsToLoad
      }
      LineComponent={DataComponentLine}
      DummyLineComponent={DataComponentLineDummy}
      dataColumns={dataColumns}
      paginationOptions={paginationOptions}
      nbOfRowsToLoad={nbOfRowsToLoad}
      onLabelClick={onLabelClick}
    />
  );
};

export default DataComponentsLines;
