import { graphql } from 'react-relay';

export const stixCyberObservablesLinesSubTypesQuery = graphql`
  query StixCyberObservablesLinesSubTypesQuery($type: String!) {
    subTypes(type: $type) {
      edges {
        node {
          id
          label
        }
      }
    }
  }
`;

export const stixCyberObservablesLinesAttributesQuery = graphql`
  query StixCyberObservablesLinesAttributesQuery($elementType: [String]!) {
    schemaAttributeNames(elementType: $elementType) {
      edges {
        node {
          value
        }
      }
    }
  }
`;

export const stixCyberObservablesLinesQuery = graphql`
  query StixCyberObservablesLinesPaginationQuery(
    $types: [String]
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: StixCyberObservablesOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...StixCyberObservablesLines_data
      @arguments(
        types: $types
        search: $search
        count: $count
        cursor: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
        filters: $filters
      )
  }
`;

export const stixCyberObservablesLinesSearchQuery = graphql`
  query StixCyberObservablesLinesSearchQuery(
    $types: [String]
    $search: String
    $filters: FilterGroup
    $count: Int
  ) {
    stixCyberObservables(
      types: $types
      search: $search
      filters: $filters
      first: $count
    ) {
      edges {
        node {
          id
          standard_id
          entity_type
          observable_value
          created_at
          updated_at
        }
      }
    }
  }
`;

export const stixCyberObservablesLinesFragment = graphql`
  fragment StixCyberObservablesLines_data on Query
  @argumentDefinitions(
    types: { type: "[String]" }
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: {
      type: "StixCyberObservablesOrdering"
      defaultValue: created_at
    }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "StixCyberObservablesLinesRefetchQuery") {
    stixCyberObservables(
      types: $types
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_stixCyberObservables") {
      edges {
        node {
          id
          standard_id
          entity_type
          observable_value
          created_at
          objectMarking {
            id
            definition
            x_opencti_order
            x_opencti_color
          }
          ...StixCyberObservableLine_node
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
