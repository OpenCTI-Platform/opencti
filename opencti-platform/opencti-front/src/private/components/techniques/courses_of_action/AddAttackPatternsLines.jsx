import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer, graphql } from 'react-relay';
import { compose } from 'ramda';
import inject18n from '../../../../components/i18n';
import StixCoreRelationshipCreationFromEntityList from '../../common/stix_core_relationships/StixCoreRelationshipCreationFromEntityList';

export const addAttackPatternsLinesMutationRelationDelete = graphql`
  mutation AddAttackPatternsLinesRelationDeleteMutation(
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

class AddAttackPatternsLinesContainer extends Component {
  render() {
    const { data, courseOfActionAttackPatterns, courseOfAction } = this.props;
    return (
      <StixCoreRelationshipCreationFromEntityList
        entity={courseOfAction}
        relationshipType={'mitigates'}
        availableDatas={data?.attackPatterns}
        existingDatas={courseOfActionAttackPatterns}
        updaterOptions={{ path: 'attackPatterns' }}
      />
    );
  }
}

AddAttackPatternsLinesContainer.propTypes = {
  courseOfAction: PropTypes.object,
  courseOfActionAttackPatterns: PropTypes.array,
  data: PropTypes.object,
};

export const addAttackPatternsLinesQuery = graphql`
  query AddAttackPatternsLinesQuery(
    $search: String
    $count: Int
    $cursor: ID
  ) {
    ...AddAttackPatternsLines_data
      @arguments(search: $search, count: $count, cursor: $cursor)
  }
`;

const AddAttackPatternsLines = createPaginationContainer(
  AddAttackPatternsLinesContainer,
  {
    data: graphql`
      fragment AddAttackPatternsLines_data on Query
      @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
      ) {
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
    `,
  },
  {
    direction: 'forward',
    getConnectionFromProps(props) {
      return props.data && props.data.attackPatterns;
    },
    getFragmentVariables(prevVars, totalCount) {
      return {
        ...prevVars,
        count: totalCount,
      };
    },
    getVariables(props, { count, cursor }, fragmentVariables) {
      return {
        count,
        cursor,
        orderBy: fragmentVariables.orderBy,
        orderMode: fragmentVariables.orderMode,
      };
    },
    query: addAttackPatternsLinesQuery,
  },
);

export default compose(inject18n)(AddAttackPatternsLines);
