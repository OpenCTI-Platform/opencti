import { graphql } from 'react-relay';

export const notificationsLinesQuery = graphql`
  query NotificationsLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: NotificationsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
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

export const notificationsLinesFragment = graphql`
  fragment NotificationsLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "NotificationsOrdering", defaultValue: created }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "NotificationsLinesRefetchQuery") {
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
