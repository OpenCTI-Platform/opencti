import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import { NotifierLine, NotifierLineDummy } from './NotifierLine';
import { NotifierLine_node$data } from './__generated__/NotifierLine_node.graphql';
import {
  NotifierLinesPaginationQuery,
  NotifierLinesPaginationQuery$variables,
} from './__generated__/NotifierLinesPaginationQuery.graphql';
import { NotifierLines_data$key } from './__generated__/NotifierLines_data.graphql';
import { HandleAddFilter, UseLocalStorageHelpers } from '../../../../../utils/hooks/useLocalStorage';
import { DataColumns } from '../../../../../components/list_lines';
import usePreloadedPaginationFragment from '../../../../../utils/hooks/usePreloadedPaginationFragment';
import ListLinesContent from '../../../../../components/list_lines/ListLinesContent';

const nbOfRowsToLoad = 50;

const NotifierLineFragment = graphql`
  fragment NotifierLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "NotifierOrdering", defaultValue: created }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    filters: { type: "[NotifierFiltering!]" }
  )
  @refetchable(queryName: "NotifierLinesRefetchQuery") {
    notifiers(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_notifiers") {
      edges {
        node {
          ...NotifierLine_node
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

export const NotifierLinesQuery = graphql`
  query NotifierLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: NotifierOrdering
    $orderMode: OrderingMode
    $filters: [NotifierFiltering!]
  ) {
    ...NotifierLines_data
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

interface NotifierLinesProps {
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
  dataColumns: DataColumns;
  paginationOptions: NotifierLinesPaginationQuery$variables;
  queryRef: PreloadedQuery<NotifierLinesPaginationQuery>;
  selectedElements: Record<string, NotifierLine_node$data>;
  deSelectedElements: Record<string, NotifierLine_node$data>;
  onToggleEntity: (entity: NotifierLine_node$data, event: React.SyntheticEvent) => void;
  selectAll: boolean;
  onLabelClick?: HandleAddFilter;
}

const NotifierLines: FunctionComponent<NotifierLinesProps> = ({
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
  const {
    data,
    hasMore,
    loadMore,
    isLoadingMore,
  } = usePreloadedPaginationFragment<NotifierLinesPaginationQuery, NotifierLines_data$key>({
    linesQuery: NotifierLinesQuery,
    linesFragment: NotifierLineFragment,
    queryRef,
    nodePath: ['notifiers', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });

  return (
    <ListLinesContent
      initialLoading={!data}
      loadMore={loadMore}
      hasMore={hasMore}
      isLoading={isLoadingMore}
      dataList={data?.notifiers?.edges ?? []}
      globalCount={data?.notifiers?.pageInfo?.globalCount ?? nbOfRowsToLoad}
      LineComponent={NotifierLine}
      DummyLineComponent={NotifierLineDummy}
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

export default NotifierLines;
