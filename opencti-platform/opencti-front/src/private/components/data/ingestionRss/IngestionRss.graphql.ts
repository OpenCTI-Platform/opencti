import { graphql } from 'react-relay';

export const ingestionRssLineFragment = graphql`
  fragment IngestionRssLine_ingestionRss on IngestionRss {
    id
    name
    uri
    ingestion_running
    current_state_date
    last_execution_date
  }
`;

export const ingestionRssLinesQuery = graphql`
  query IngestionRssLinesDataTableQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: IngestionRssOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...IngestionRssLinesDataTable_data
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

export const ingestionRssLinesFragment = graphql`
  fragment IngestionRssLinesDataTable_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "IngestionRssOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "IngestionRssLinesDataTableRefetchQuery") {
    ingestionRsss(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_ingestionRsss") {
      edges {
        node {
          id
          ...IngestionRssLine_ingestionRss
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
