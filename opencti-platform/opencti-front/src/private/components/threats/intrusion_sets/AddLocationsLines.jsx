import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer, graphql } from 'react-relay';
import { compose } from 'ramda';
import inject18n from '../../../../components/i18n';
import StixCoreRelationshipCreationFromEntityList from '../../common/stix_core_relationships/StixCoreRelationshipCreationFromEntityList';

export const addLocationsMutationRelationDelete = graphql`
  mutation AddLocationsLinesRelationDeleteMutation(
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

class AddLocationsLinesContainer extends Component {
  render() {
    const { data, intrusionSetLocations, intrusionSet } = this.props;
    return (
      <StixCoreRelationshipCreationFromEntityList
        entity={intrusionSet}
        relationshipType={'originates-from'}
        availableDatas={data?.locations}
        existingDatas={intrusionSetLocations}
        updaterOptions={{ path: 'locations' }}
      />
    );
  }
}

AddLocationsLinesContainer.propTypes = {
  intrusionSet: PropTypes.object,
  intrusionSetLocations: PropTypes.array,
  data: PropTypes.object,
};

export const addLocationsLinesQuery = graphql`
  query AddLocationsLinesQuery($search: String, $count: Int, $cursor: ID) {
    ...AddLocationsLines_data
      @arguments(search: $search, count: $count, cursor: $cursor)
  }
`;

const AddLocationsLines = createPaginationContainer(
  AddLocationsLinesContainer,
  {
    data: graphql`
      fragment AddLocationsLines_data on Query
      @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
      ) {
        locations(search: $search, first: $count, after: $cursor)
          @connection(key: "Pagination_locations") {
          edges {
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
    query: addLocationsLinesQuery,
  },
);

export default compose(inject18n)(AddLocationsLines);
