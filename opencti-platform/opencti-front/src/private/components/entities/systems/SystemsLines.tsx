import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import { SystemsLinesPaginationQuery, SystemsLinesPaginationQuery$variables } from '@components/entities/systems/__generated__/SystemsLinesPaginationQuery.graphql';
import { SystemsLines_data$key } from '@components/entities/systems/__generated__/SystemsLines_data.graphql';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { SystemLine, SystemLineDummy } from './SystemLine';
import { DataColumns } from '../../../../components/list_lines';
import { HandleAddFilter, UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';

const nbOfRowsToLoad = 50;

interface SystemsLinesProps {
  queryRef: PreloadedQuery<SystemsLinesPaginationQuery>;
  dataColumns: DataColumns;
  paginationOptions?: SystemsLinesPaginationQuery$variables;
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
  onLabelClick: HandleAddFilter;
}

export const systemsLinesQuery = graphql`
  query SystemsLinesPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: SystemsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...SystemsLines_data
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

const systemsLinesFragment = graphql`
  fragment SystemsLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "SystemsOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "SystemsLinesRefetchQuery") {
    systems(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_systems") {
      edges {
        node {
          id
          name
          description
          ...SystemLine_node
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

const SystemsLines: FunctionComponent<SystemsLinesProps> = ({
  setNumberOfElements,
  queryRef,
  dataColumns,
  paginationOptions,
  onLabelClick,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  SystemsLinesPaginationQuery,
  SystemsLines_data$key
  >({
    linesQuery: systemsLinesQuery,
    linesFragment: systemsLinesFragment,
    queryRef,
    nodePath: ['systems', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });
  return (
    <ListLinesContent
      initialLoading={!data}
      loadMore={loadMore}
      hasMore={hasMore}
      isLoading={isLoadingMore}
      dataList={data?.systems?.edges ?? []}
      globalCount={
        data?.systems?.pageInfo?.globalCount ?? nbOfRowsToLoad
      }
      LineComponent={SystemLine}
      DummyLineComponent={SystemLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
      onLabelClick={onLabelClick}
    />
  );
};

export default SystemsLines;
