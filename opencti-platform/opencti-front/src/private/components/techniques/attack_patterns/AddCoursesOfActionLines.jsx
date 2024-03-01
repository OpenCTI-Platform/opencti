import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer, graphql } from 'react-relay';
import { compose } from 'ramda';
import inject18n from '../../../../components/i18n';
import StixCoreRelationshipCreationFromEntityList from '../../common/stix_core_relationships/StixCoreRelationshipCreationFromEntityList';

export const addCoursesOfActionMutationRelationDelete = graphql`
  mutation AddCoursesOfActionLinesRelationDeleteMutation(
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

class AddCoursesOfActionLinesContainer extends Component {
  render() {
    const { data, attackPatternCoursesOfAction, attackPattern } = this.props;
    return (
      <StixCoreRelationshipCreationFromEntityList
        entity={attackPattern}
        relationshipType={'mitigates'}
        availableDatas={data?.coursesOfAction}
        existingDatas={attackPatternCoursesOfAction}
        updaterOptions={{ path: 'coursesOfAction' }}
        isRelationReversed={true}
      />
    );
  }
}

AddCoursesOfActionLinesContainer.propTypes = {
  attackPattern: PropTypes.object,
  attackPatternCoursesOfAction: PropTypes.array,
  data: PropTypes.object,
};

export const addCoursesOfActionLinesQuery = graphql`
  query AddCoursesOfActionLinesQuery(
    $search: String
    $count: Int
    $cursor: ID
  ) {
    ...AddCoursesOfActionLines_data
      @arguments(search: $search, count: $count, cursor: $cursor)
  }
`;

const AddCoursesOfActionLines = createPaginationContainer(
  AddCoursesOfActionLinesContainer,
  {
    data: graphql`
      fragment AddCoursesOfActionLines_data on Query
      @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
      ) {
        coursesOfAction(search: $search, first: $count, after: $cursor)
          @connection(key: "Pagination_coursesOfAction") {
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
      return props.data && props.data.coursesOfAction;
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
    query: addCoursesOfActionLinesQuery,
  },
);

export default compose(inject18n)(AddCoursesOfActionLines);
