import { graphql, PreloadedQuery } from 'react-relay';
import React, { FunctionComponent } from 'react';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { AddDataComponentsLinesQuery } from './__generated__/AddDataComponentsLinesQuery.graphql';
import { AddDataComponentsLines_data$key } from './__generated__/AddDataComponentsLines_data.graphql';
import { AttackPatternDataComponents_attackPattern$data } from './__generated__/AttackPatternDataComponents_attackPattern.graphql';
import StixCoreRelationshipCreationFromEntityList from '../../common/stix_core_relationships/StixCoreRelationshipCreationFromEntityList';

export const addDataComponentsMutationRelationDelete = graphql`
  mutation AddDataComponentsLinesRelationDeleteMutation(
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

export const addDataComponentsLinesQuery = graphql`
  query AddDataComponentsLinesQuery(
    $search: String
    $count: Int
    $cursor: ID
  ) {
    ...AddDataComponentsLines_data
      @arguments(search: $search, count: $count, cursor: $cursor)
  }
`;

export const addDataComponentsLinesFragment = graphql`
  fragment AddDataComponentsLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
  )
  @refetchable(queryName: "AddDataComponentsLinesRefetchQuery") {
    dataComponents(search: $search, first: $count, after: $cursor)
      @connection(key: "Pagination_dataComponents") {
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

interface AddDataComponentsLinesContainerProps {
  attackPattern: AttackPatternDataComponents_attackPattern$data;
  queryRef: PreloadedQuery<AddDataComponentsLinesQuery>;
}

const AddDataComponentsLines: FunctionComponent<
AddDataComponentsLinesContainerProps
> = ({ attackPattern, queryRef }) => {
  const { data } = usePreloadedPaginationFragment<
  AddDataComponentsLinesQuery,
  AddDataComponentsLines_data$key
  >({
    linesQuery: addDataComponentsLinesQuery,
    linesFragment: addDataComponentsLinesFragment,
    queryRef,
  });
  return (
    <StixCoreRelationshipCreationFromEntityList
      entity={attackPattern}
      relationshipType={'detects'}
      availableDatas={data.dataComponents}
      existingDatas={attackPattern.dataComponents?.edges}
      updaterOptions={{ path: 'dataComponents' }}
      isRelationReversed={true}
    />
  );
};

export default AddDataComponentsLines;
