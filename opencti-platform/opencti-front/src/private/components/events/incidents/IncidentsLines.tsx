import { graphql } from 'react-relay';

export const incidentsLinesQuery = graphql`
  query IncidentsLinesQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: IncidentsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...IncidentsLines_data
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

export const incidentsLinesFragment = graphql`
  fragment IncidentsLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "IncidentsOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "IncidentsLinesRefetchQuery") {
    incidents(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_incidents") {
      edges {
        node {
          id
          name
          description
          ...IncidentLine_node
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
