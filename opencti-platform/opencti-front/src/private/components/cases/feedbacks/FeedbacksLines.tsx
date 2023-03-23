import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { DataColumns } from '../../../../components/list_lines';
import { UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { FeedbackLine, FeedbackLineDummy } from './FeedbackLine';
import {
  FeedbacksLinesPaginationQuery,
  FeedbacksLinesPaginationQuery$variables,
} from './__generated__/FeedbacksLinesPaginationQuery.graphql';
import { FeedbacksLines_data$key } from './__generated__/FeedbacksLines_data.graphql';
import { FeedbackLine_node$data } from './__generated__/FeedbackLine_node.graphql';

const nbOfRowsToLoad = 50;

interface FeedbacksLinesProps {
  paginationOptions?: FeedbacksLinesPaginationQuery$variables;
  dataColumns: DataColumns;
  queryRef: PreloadedQuery<FeedbacksLinesPaginationQuery>;
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
  selectedElements: Record<string, FeedbackLine_node$data>;
  deSelectedElements: Record<string, FeedbackLine_node$data>;
  onToggleEntity: (
    entity: FeedbackLine_node$data,
    event: React.SyntheticEvent
  ) => void;
  selectAll: boolean;
}

export const feedbacksLinesQuery = graphql`
  query FeedbacksLinesPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: FeedbacksOrdering
    $orderMode: OrderingMode
    $filters: [FeedbacksFiltering!]
  ) {
    ...FeedbacksLines_data
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

const feedbacksLinesFragment = graphql`
  fragment FeedbacksLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int" }
    cursor: { type: "ID" }
    orderBy: { type: "FeedbacksOrdering" }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    filters: { type: "[FeedbacksFiltering!]" }
  )
  @refetchable(queryName: "FeedbackLinesRefetchQuery") {
    feedbacks(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_feedbacks") {
      edges {
        node {
          id
          ...FeedbackLine_node
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

const FeedbacksLines: FunctionComponent<FeedbacksLinesProps> = ({
  setNumberOfElements,
  dataColumns,
  queryRef,
  paginationOptions,
  selectedElements,
  deSelectedElements,
  selectAll,
  onToggleEntity,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  FeedbacksLinesPaginationQuery,
  FeedbacksLines_data$key
  >({
    linesQuery: feedbacksLinesQuery,
    linesFragment: feedbacksLinesFragment,
    queryRef,
    nodePath: ['feedbacks', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });
  return (
    <ListLinesContent
      initialLoading={!data}
      hasMore={hasMore}
      loadMore={loadMore}
      isLoading={isLoadingMore}
      dataList={data?.feedbacks?.edges ?? []}
      globalCount={data?.feedbacks?.pageInfo?.globalCount ?? nbOfRowsToLoad}
      LineComponent={FeedbackLine}
      DummyLineComponent={FeedbackLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
      selectedElements={selectedElements}
      deSelectedElements={deSelectedElements}
      onToggleEntity={onToggleEntity}
      selectAll={selectAll}
    />
  );
};

export default FeedbacksLines;
