import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { ToolLine, ToolLineDummy } from './ToolLine';
import { DataColumns } from '../../../../components/list_lines';
import { HandleAddFilter, UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { ToolsLinesPaginationQuery, ToolsLinesPaginationQuery$variables } from './__generated__/ToolsLinesPaginationQuery.graphql';
import { ToolsLines_data$key } from './__generated__/ToolsLines_data.graphql';

const nbOfRowsToLoad = 50;

interface ToolsLinesProps {
  queryRef: PreloadedQuery<ToolsLinesPaginationQuery>;
  dataColumns: DataColumns;
  paginationOptions?: ToolsLinesPaginationQuery$variables;
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
  onLabelClick: HandleAddFilter;
}

export const toolsLinesQuery = graphql`
  query ToolsLinesPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: ToolsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...ToolsLines_data
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

const toolsLinesFragment = graphql`
  fragment ToolsLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "ToolsOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "ToolsLinesRefetchQuery") {
    tools(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_tools") {
      edges {
        node {
          id
          name
          description
          ...ToolLine_node
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

const ToolsLines: FunctionComponent<ToolsLinesProps> = ({
  setNumberOfElements,
  queryRef,
  dataColumns,
  paginationOptions,
  onLabelClick,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  ToolsLinesPaginationQuery,
  ToolsLines_data$key
  >({
    linesQuery: toolsLinesQuery,
    linesFragment: toolsLinesFragment,
    queryRef,
    nodePath: ['tools', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });

  return (
    <ListLinesContent
      initialLoading={!data}
      loadMore={loadMore}
      hasMore={hasMore}
      isLoading={isLoadingMore}
      dataList={data?.tools?.edges ?? []}
      globalCount={
        data?.tools?.pageInfo?.globalCount ?? nbOfRowsToLoad
      }
      LineComponent={ToolLine}
      DummyLineComponent={ToolLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
      onLabelClick={onLabelClick}
    />
  );
};

export default ToolsLines;
