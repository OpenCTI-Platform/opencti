import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import { SearchLogLine, SearchLogLineDummy } from './SearchLogLine';
import { SearchLogLine_node$data } from '../__generated__/SearchLogLine_node.graphql';
import { SearchLogLinesPaginationQuery, SearchLogLinesPaginationQuery$variables } from '../__generated__/SearchLogLinesPaginationQuery.graphql';
import { SearchLogLines_data$key } from '../__generated__/SearchLogLines_data.graphql';
import { HandleAddFilter, UseLocalStorageHelpers } from '../../../../../../utils/hooks/useLocalStorage';
import { DataColumns } from '../../../../../../components/list_lines';
import usePreloadedPaginationFragment from '../../../../../../utils/hooks/usePreloadedPaginationFragment';
import ListLinesContent from '../../../../../../components/list_lines/ListLinesContent';

const nbOfRowsToLoad = 50;

const SearchLogLineFragment = graphql`
  fragment SearchLogLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    types: { type: "[String!]" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "LogsOrdering", defaultValue: timestamp }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "SearchLogLinesRefetchQuery") {
    searchLogs(
      search: $search
      first: $count
      types: $types
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_searchLogs") {
      edges {
        node {
          ...SearchLogLine_node
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

export const SearchLogLinesQuery = graphql`
  query SearchLogLinesPaginationQuery(
    $search: String
    $types: [String!]
    $count: Int!
    $cursor: ID
    $orderBy: LogsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...SearchLogLines_data
      @arguments(
        search: $search
        types: $types
        count: $count
        cursor: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
        filters: $filters
      )
  }
`;

interface SearchLogLinesProps {
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
  dataColumns: DataColumns;
  paginationOptions: SearchLogLinesPaginationQuery$variables;
  queryRef: PreloadedQuery<SearchLogLinesPaginationQuery>;
  selectedElements: Record<string, SearchLogLine_node$data>;
  deSelectedElements: Record<string, SearchLogLine_node$data>;
  onToggleEntity: (
    entity: SearchLogLine_node$data,
    event: React.SyntheticEvent,
  ) => void;
  selectAll: boolean;
  onLabelClick?: HandleAddFilter;
}

const SearchLogLines: FunctionComponent<SearchLogLinesProps> = ({
  paginationOptions,
  queryRef,
  dataColumns,
  onLabelClick,
  setNumberOfElements,
  onToggleEntity,
  selectedElements,
  deSelectedElements,
  selectAll,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
    SearchLogLinesPaginationQuery,
    SearchLogLines_data$key
  >({
    linesQuery: SearchLogLinesQuery,
    linesFragment: SearchLogLineFragment,
    queryRef,
    nodePath: ['searchLogs', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });
  return (
    <ListLinesContent
      initialLoading={!data}
      loadMore={loadMore}
      hasMore={hasMore}
      isLoading={isLoadingMore}
      dataList={data?.searchLogs?.edges ?? []}
      globalCount={data?.searchLogs?.pageInfo?.globalCount ?? nbOfRowsToLoad}
      LineComponent={SearchLogLine}
      DummyLineComponent={SearchLogLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
      onLabelClick={onLabelClick}
      selectedElements={selectedElements}
      deSelectedElements={deSelectedElements}
      selectAll={selectAll}
      onToggleEntity={onToggleEntity}
    />
  );
};

export default SearchLogLines;
