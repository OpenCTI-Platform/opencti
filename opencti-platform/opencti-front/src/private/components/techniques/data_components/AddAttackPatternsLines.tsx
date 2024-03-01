import { graphql, PreloadedQuery } from 'react-relay';
import React, { FunctionComponent } from 'react';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { AddAttackPatternsLinesToDataComponentQuery } from './__generated__/AddAttackPatternsLinesToDataComponentQuery.graphql';
import { DataComponentAttackPatterns_dataComponent$data } from './__generated__/DataComponentAttackPatterns_dataComponent.graphql';
import { AddAttackPatternsLinesToDataComponent_data$key } from './__generated__/AddAttackPatternsLinesToDataComponent_data.graphql';
import StixCoreRelationshipCreationFromEntityList from '../../common/stix_core_relationships/StixCoreRelationshipCreationFromEntityList';

export const addAttackPatternsMutationRelationDelete = graphql`
  mutation AddAttackPatternsLinesToDataComponentRelationDeleteMutation(
    $fromId: StixRef!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    stixCoreRelationshipDelete(
      fromId: $fromId
      toId: $toId
      relationship_type: $relationship_type
    )
  }
`;

export const addAttackPatternsLinesQuery = graphql`
  query AddAttackPatternsLinesToDataComponentQuery(
    $search: String
    $count: Int
    $cursor: ID
  ) {
    ...AddAttackPatternsLinesToDataComponent_data
      @arguments(search: $search, count: $count, cursor: $cursor)
  }
`;

export const addAttackPatternsLinesFragment = graphql`
  fragment AddAttackPatternsLinesToDataComponent_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
  )
  @refetchable(queryName: "AddAttackPatternsLinesRefetchQuery") {
    attackPatterns(search: $search, first: $count, after: $cursor)
      @connection(key: "Pagination_attackPatterns") {
      edges {
        node {
          id
          entity_type
          parent_types
          name
          description
        }
      }
    }
  }
`;

interface AddAttackPatternsLinesContainerProps {
  dataComponent: DataComponentAttackPatterns_dataComponent$data;
  queryRef: PreloadedQuery<AddAttackPatternsLinesToDataComponentQuery>;
}

const AddAttackPatternsLines: FunctionComponent<
AddAttackPatternsLinesContainerProps
> = ({ dataComponent, queryRef }) => {
  const { data } = usePreloadedPaginationFragment<
  AddAttackPatternsLinesToDataComponentQuery,
  AddAttackPatternsLinesToDataComponent_data$key
  >({
    linesQuery: addAttackPatternsLinesQuery,
    linesFragment: addAttackPatternsLinesFragment,
    queryRef,
  });

  const attackPatterns = dataComponent.attackPatterns?.edges;

  return (
    <StixCoreRelationshipCreationFromEntityList
      entity={dataComponent}
      relationshipType={'detects'}
      availableDatas={data?.attackPatterns}
      existingDatas={attackPatterns}
      updaterOptions={{ path: 'attackPatterns' }}
      isRelationReversed={false}
    />
  );
};

export default AddAttackPatternsLines;
