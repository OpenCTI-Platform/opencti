import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { DataColumns } from '../../../../components/list_lines';
import type { UseLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { FeedbackLine, FeedbackLineDummy } from './FeedbackLine';
import {
  FeedbacksLinesPaginationQuery,
  FeedbacksLinesPaginationQuery$variables,
} from './__generated__/FeedbacksLinesPaginationQuery.graphql';
import { FeedbacksLines_data$key } from './__generated__/FeedbacksLines_data.graphql';
import { FeedbackLine_node$data } from './__generated__/FeedbackLine_node.graphql';

const nbOfRowsToLoad = 50;

interface CasesLinesProps {
  paginationOptions?: FeedbacksLinesPaginationQuery$variables;
  dataColumns: DataColumns;
  queryRef: PreloadedQuery<FeedbacksLinesPaginationQuery>;
  setNumberOfElements: UseLocalStorage[2]['handleSetNumberOfElements'];
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
    $orderBy: CasesOrdering
    $orderMode: OrderingMode
    $filters: [CasesFiltering!]
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
    orderBy: { type: "CasesOrdering" }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    filters: { type: "[CasesFiltering!]" }
  )
  @refetchable(queryName: "FeedbackLinesRefetchQuery") {
    cases(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_cases") {
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

const FeedbacksLines: FunctionComponent<CasesLinesProps> = ({
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
    nodePath: ['cases', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });
  return (
    <ListLinesContent
      initialLoading={!data}
      hasMore={hasMore}
      loadMore={loadMore}
      isLoading={isLoadingMore}
      dataList={data?.cases?.edges ?? []}
      globalCount={data?.cases?.pageInfo?.globalCount ?? nbOfRowsToLoad}
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
