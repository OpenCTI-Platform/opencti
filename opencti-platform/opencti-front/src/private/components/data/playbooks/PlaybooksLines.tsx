import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import { DataColumns } from '../../../../components/list_lines';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { PlaybookLineComponent, PlaybookLineDummy } from './PlaybookLine';
import { PlaybooksLinesPaginationQuery, PlaybooksLinesPaginationQuery$variables } from './__generated__/PlaybooksLinesPaginationQuery.graphql';
import { PlaybooksLines_data$key } from './__generated__/PlaybooksLines_data.graphql';

const nbOfRowsToLoad = 50;

interface PlaybookLinesProps {
  queryRef: PreloadedQuery<PlaybooksLinesPaginationQuery>;
  dataColumns: DataColumns;
  paginationOptions?: PlaybooksLinesPaginationQuery$variables;
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
}

export const playbooksLinesQuery = graphql`
  query PlaybooksLinesPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: PlaybooksOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...PlaybooksLines_data
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

const playbooksLinesFragment = graphql`
  fragment PlaybooksLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "PlaybooksOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "PlaybooksLinesRefetchQuery") {
    playbooks(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_playbooks") {
      edges {
        node {
          id
          name
          description
          ...PlaybookLine_node
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

const PlaybooksLines: FunctionComponent<PlaybookLinesProps> = ({
  setNumberOfElements,
  queryRef,
  dataColumns,
  paginationOptions,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  PlaybooksLinesPaginationQuery,
  PlaybooksLines_data$key
  >({
    linesQuery: playbooksLinesQuery,
    linesFragment: playbooksLinesFragment,
    queryRef,
    nodePath: ['playbooks', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });

  return (
    <ListLinesContent
      initialLoading={!data}
      isLoading={isLoadingMore}
      loadMore={loadMore}
      hasMore={hasMore}
      dataList={data?.playbooks?.edges ?? []}
      globalCount={data?.playbooks?.pageInfo?.globalCount ?? nbOfRowsToLoad}
      LineComponent={PlaybookLineComponent}
      DummyLineComponent={PlaybookLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
    />
  );
};

export default PlaybooksLines;
