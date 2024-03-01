import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer, graphql } from 'react-relay';
import { compose } from 'ramda';
import StixCoreRelationshipCreationFromEntityList from '../../common/stix_core_relationships/StixCoreRelationshipCreationFromEntityList';
import inject18n from '../../../../components/i18n';

export const addSubNarrativesMutationRelationDelete = graphql`
  mutation AddSubNarrativesLinesRelationDeleteMutation(
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

class AddSubNarrativesLinesContainer extends Component {
  render() {
    const { data, narrativeSubNarratives, narrative } = this.props;
    return (
      <StixCoreRelationshipCreationFromEntityList
        entity={narrative}
        relationshipType={'subnarrative-of'}
        availableDatas={data?.narratives}
        existingDatas={narrativeSubNarratives}
        updaterOptions={{ path: 'subNarratives' }}
        isRelationReversed={true}
      />
    );
  }
}

AddSubNarrativesLinesContainer.propTypes = {
  narrative: PropTypes.object,
  narrativeSubNarratives: PropTypes.array,
  data: PropTypes.object,
};

export const addSubNarrativesLinesQuery = graphql`
  query AddSubNarrativesLinesQuery($search: String, $count: Int, $cursor: ID) {
    ...AddSubNarrativesLines_data
      @arguments(search: $search, count: $count, cursor: $cursor)
  }
`;

const AddSubNarrativesLines = createPaginationContainer(
  AddSubNarrativesLinesContainer,
  {
    data: graphql`
      fragment AddSubNarrativesLines_data on Query
      @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
      ) {
        narratives(search: $search, first: $count, after: $cursor)
          @connection(key: "Pagination_narratives") {
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
      return props.data && props.data.subNarratives;
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
    query: addSubNarrativesLinesQuery,
  },
);

export default compose(inject18n)(AddSubNarrativesLines);
