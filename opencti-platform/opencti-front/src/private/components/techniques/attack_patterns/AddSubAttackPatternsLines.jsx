import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer, graphql } from 'react-relay';
import { compose } from 'ramda';
import inject18n from '../../../../components/i18n';
import StixCoreRelationshipCreationFromEntityList from '../../common/stix_core_relationships/StixCoreRelationshipCreationFromEntityList';

export const addSubAttackPatternsMutationRelationDelete = graphql`
  mutation AddSubAttackPatternsLinesRelationDeleteMutation(
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

class AddSubAttackPatternsLinesContainer extends Component {
  render() {
    const { data, attackPatternSubAttackPatterns, attackPattern } = this.props;
    return (
      <StixCoreRelationshipCreationFromEntityList
        entity={attackPattern}
        relationshipType={'subtechnique-of'}
        availableDatas={data?.attackPatterns}
        existingDatas={attackPatternSubAttackPatterns}
        updaterOptions={{ path: 'subAttackPatterns' }}
        isRelationReversed={true}
      />
    );
  }
}

AddSubAttackPatternsLinesContainer.propTypes = {
  attackPattern: PropTypes.object,
  attackPatternSubAttackPatterns: PropTypes.array,
  data: PropTypes.object,
};

export const addSubAttackPatternsLinesQuery = graphql`
  query AddSubAttackPatternsLinesQuery(
    $search: String
    $count: Int
    $cursor: ID
  ) {
    ...AddSubAttackPatternsLines_data
      @arguments(search: $search, count: $count, cursor: $cursor)
  }
`;

const AddSubAttackPatternsLines = createPaginationContainer(
  AddSubAttackPatternsLinesContainer,
  {
    data: graphql`
      fragment AddSubAttackPatternsLines_data on Query
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
              x_mitre_id
            }
          }
        }
      }
    `,
  },
  {
    direction: 'forward',
    getConnectionFromProps(props) {
      return props.data && props.data.subAttackPatterns;
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
    query: addSubAttackPatternsLinesQuery,
  },
);

export default compose(inject18n)(AddSubAttackPatternsLines);
