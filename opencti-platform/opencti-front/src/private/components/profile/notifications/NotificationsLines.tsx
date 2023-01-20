import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import { DataColumns } from '../../../../components/list_lines';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import {
  NotificationLineComponent,
  NotificationLineDummy,
} from './NotificationLine';
import {
  NotificationsLinesPaginationQuery,
  NotificationsLinesPaginationQuery$variables,
} from './__generated__/NotificationsLinesPaginationQuery.graphql';
import { NotificationsLines_data$key } from './__generated__/NotificationsLines_data.graphql';
import { NotificationLine_node$data } from './__generated__/NotificationLine_node.graphql';

const nbOfRowsToLoad = 50;

interface NotificationLinesProps {
  queryRef: PreloadedQuery<NotificationsLinesPaginationQuery>;
  dataColumns: DataColumns;
  paginationOptions?: NotificationsLinesPaginationQuery$variables;
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
  onLabelClick: (
    k: string,
    id: string,
    value: Record<string, unknown>,
    event: React.KeyboardEvent
  ) => void;
  selectedElements: Record<string, NotificationLine_node$data>;
  deSelectedElements: Record<string, NotificationLine_node$data>;
  onToggleEntity: (
    entity: NotificationLine_node$data,
    event: React.SyntheticEvent
  ) => void;
  selectAll: boolean;
}

export const notificationsLinesQuery = graphql`
  query NotificationsLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: NotificationsOrdering
    $orderMode: OrderingMode
    $filters: [NotificationsFiltering!]
  ) {
    ...NotificationsLines_data
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

const notificationsLinesFragment = graphql`
  fragment NotificationsLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "NotificationsOrdering", defaultValue: created }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "[NotificationsFiltering!]" }
  )
  @refetchable(queryName: "AlertsLinesRefetchQuery") {
    myNotifications(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_myNotifications") {
      edges {
        node {
          id
          ...NotificationLine_node
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

const NotificationsLines: FunctionComponent<NotificationLinesProps> = ({
  setNumberOfElements,
  queryRef,
  dataColumns,
  paginationOptions,
  onLabelClick,
  selectedElements,
  deSelectedElements,
  selectAll,
  onToggleEntity,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  NotificationsLinesPaginationQuery,
  NotificationsLines_data$key
  >({
    linesQuery: notificationsLinesQuery,
    linesFragment: notificationsLinesFragment,
    queryRef,
    nodePath: ['myNotifications', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });

  return (
    <ListLinesContent
      initialLoading={!data}
      isLoading={isLoadingMore}
      loadMore={loadMore}
      hasMore={hasMore}
      dataList={data?.myNotifications?.edges ?? []}
      globalCount={data?.myNotifications?.pageInfo?.globalCount ?? nbOfRowsToLoad}
      LineComponent={NotificationLineComponent}
      DummyLineComponent={NotificationLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
      onLabelClick={onLabelClick}
      selectedElements={selectedElements}
      deSelectedElements={deSelectedElements}
      onToggleEntity={onToggleEntity}
      selectAll={selectAll}
    />
  );
};

export default NotificationsLines;
