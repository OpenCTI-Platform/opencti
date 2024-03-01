import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer, graphql } from 'react-relay';
import { compose } from 'ramda';
import inject18n from '../../../../components/i18n';
import StixCoreRelationshipCreationFromEntityList from '../../common/stix_core_relationships/StixCoreRelationshipCreationFromEntityList';

export const addLocationsThreatActorGroupMutationRelationDelete = graphql`
  mutation AddLocationsThreatActorGroupLinesRelationDeleteMutation(
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

class AddLocationsThreatActorGroupLinesContainer extends Component {
  render() {
    const { data, threatActorGroupLocations, threatActorGroup } = this.props;
    return (
      <StixCoreRelationshipCreationFromEntityList
        entity={threatActorGroup}
        relationshipType="located-at"
        availableDatas={data?.locations}
        existingDatas={threatActorGroupLocations}
        updaterOptions={{ path: 'locations' }}
      />
    );
  }
}

AddLocationsThreatActorGroupLinesContainer.propTypes = {
  threatActorGroup: PropTypes.object,
  threatActorGroupLocations: PropTypes.array,
  data: PropTypes.object,
};

export const addLocationsThreatActorGroupLinesQuery = graphql`
  query AddLocationsThreatActorGroupLinesQuery(
    $search: String
    $count: Int
    $cursor: ID
  ) {
    ...AddLocationsThreatActorGroupLines_data
      @arguments(search: $search, count: $count, cursor: $cursor)
  }
`;

const AddLocationsThreatActorGroupLines = createPaginationContainer(
  AddLocationsThreatActorGroupLinesContainer,
  {
    data: graphql`
      fragment AddLocationsThreatActorGroupLines_data on Query
      @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
      ) {
        locations(search: $search, first: $count, after: $cursor)
          @connection(key: "Pagination_threatActorGroup_locations") {
          edges {
            types
            node {
              id
              entity_type
              parent_types
              name
              x_opencti_aliases
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
    query: addLocationsThreatActorGroupLinesQuery,
  },
);

export default compose(inject18n)(AddLocationsThreatActorGroupLines);
