import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer, graphql } from 'react-relay';
import { compose } from 'ramda';
import inject18n from '../../../../components/i18n';
import StixCoreRelationshipCreationFromEntityList from '../../common/stix_core_relationships/StixCoreRelationshipCreationFromEntityList';

export const addLocationsThreatActorMutationRelationDelete = graphql`
  mutation AddLocationsThreatActorIndividualLinesRelationDeleteMutation(
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

class AddLocationsThreatActorIndividualLinesContainer extends Component {
  render() {
    const { data, threatActorIndividualLocations, threatActorIndividual } = this.props;
    return (
      <StixCoreRelationshipCreationFromEntityList
        entity={threatActorIndividual}
        relationshipType={'located-at'}
        availableDatas={data?.locations}
        existingDatas={threatActorIndividualLocations}
        updaterOptions={{ path: 'locations' }}
      />
    );
  }
}

AddLocationsThreatActorIndividualLinesContainer.propTypes = {
  threatActorIndividual: PropTypes.object,
  threatActorIndividualLocations: PropTypes.array,
  data: PropTypes.object,
};

export const addLocationsThreatActorIndividualLinesQuery = graphql`
  query AddLocationsThreatActorIndividualLinesQuery(
    $search: String
    $count: Int
    $cursor: ID
  ) {
    ...AddLocationsThreatActorIndividualLines_data
      @arguments(search: $search, count: $count, cursor: $cursor)
  }
`;

const AddLocationsThreatActorIndividualLines = createPaginationContainer(
  AddLocationsThreatActorIndividualLinesContainer,
  {
    data: graphql`
      fragment AddLocationsThreatActorIndividualLines_data on Query
      @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
      ) {
        locations(search: $search, first: $count, after: $cursor)
          @connection(key: "Pagination_threatActorIndividual_locations") {
          edges {
            types
            node {
              id
              entity_type
              parent_types
              name
              description
              x_opencti_aliases
            }
          }
        }
      }
    `,
  },
  {
    direction: 'forward',
    getConnectionFromProps(props) {
      return props.data && props.data.locations;
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
    query: addLocationsThreatActorIndividualLinesQuery,
  },
);

export default compose(inject18n)(AddLocationsThreatActorIndividualLines);
