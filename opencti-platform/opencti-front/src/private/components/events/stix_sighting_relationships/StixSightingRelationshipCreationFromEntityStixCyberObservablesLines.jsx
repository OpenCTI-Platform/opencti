import React from 'react';
import { graphql } from 'react-relay';
import DataTableWithoutFragment from '../../../../components/dataGrid/DataTableWithoutFragment';
import ItemIcon from '../../../../components/ItemIcon';

export const stixSightingRelationshipCreationFromEntityStixCyberObservablesLinesQuery = graphql`
  query StixSightingRelationshipCreationFromEntityStixCyberObservablesLinesQuery(
    $search: String
    $types: [String]
    $count: Int!
    $cursor: ID
    $orderBy: StixCyberObservablesOrdering
    $orderMode: OrderingMode
  ) {
    ...StixSightingRelationshipCreationFromEntityStixCyberObservablesLines_data
      @arguments(
        search: $search
        types: $types
        count: $count
        cursor: $cursor
        orderBy: $orderBy
        orderMode: $orderMode
      )
  }
`;

export const stixSightingRelationshipCreationFromEntityStixCyberObservablesLinesFragment = graphql`
  fragment StixSightingRelationshipCreationFromEntityStixCyberObservablesLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    types: { type: "[String]" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "StixCyberObservablesOrdering", defaultValue: created_at }
    orderMode: { type: "OrderingMode", defaultValue: asc }
  ) {
    stixCyberObservables(
      search: $search
      types: $types
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
    ) @connection(key: "Pagination_stixCyberObservables") {
      edges {
        node {
          id
          entity_type
          parent_types
          observable_value
        }
      }
    }
  }
`;

const StixSightingRelationshipCreationFromEntityStixCyberObservablesLines = ({ data, handleSelect }) => {
  const observables = data?.stixCyberObservables?.edges?.map((edge) => edge.node) ?? [];
  if (observables.length === 0) return null;

  return (
    <DataTableWithoutFragment
      data={observables}
      globalCount={observables.length}
      dataColumns={{
        observable_value: {
          label: 'Value',
          percentWidth: 100,
          isSortable: false,
        },
      }}
      storageKey="stixSightingRelationshipCreationFromEntity-observables"
      disableNavigation
      disableLineSelection
      disableToolBar
      disableColumnMenu
      hideHeaders
      onLineClick={handleSelect}
      icon={(row) => <ItemIcon type={row.entity_type} />}
    />
  );
};

export default StixSightingRelationshipCreationFromEntityStixCyberObservablesLines;
