import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer, graphql } from 'react-relay';
import { compose } from 'ramda';
import inject18n from '../../../../components/i18n';
import StixCoreRelationshipCreationFromEntityList from '../../common/stix_core_relationships/StixCoreRelationshipCreationFromEntityList';

export const addSoftwaresMutationRelationDelete = graphql`
  mutation AddSoftwaresLinesRelationDeleteMutation(
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

class AddSoftwaresLinesContainer extends Component {
  render() {
    const { data, vulnerabilitySoftwares, vulnerability } = this.props;
    return (
      <StixCoreRelationshipCreationFromEntityList
        entity={vulnerability}
        relationshipType={'has'}
        availableDatas={data?.stixCyberObservables}
        existingDatas={vulnerabilitySoftwares}
        updaterOptions={ { path: 'softwares', params: { first: 10 } } }
        isRelationReversed={true}
      />
    );
  }
}

AddSoftwaresLinesContainer.propTypes = {
  vulnerability: PropTypes.object,
  vulnerabilitySoftwares: PropTypes.array,
  data: PropTypes.object,
};

export const addSoftwaresLinesQuery = graphql`
  query AddSoftwaresLinesQuery($search: String, $count: Int, $cursor: ID) {
    ...AddSoftwaresLines_data
      @arguments(search: $search, count: $count, cursor: $cursor)
  }
`;

const AddSoftwaresLines = createPaginationContainer(
  AddSoftwaresLinesContainer,
  {
    data: graphql`
      fragment AddSoftwaresLines_data on Query
      @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
      ) {
        stixCyberObservables(
          types: ["Software"]
          search: $search
          first: $count
          after: $cursor
        ) @connection(key: "Pagination_stixCyberObservables") {
          edges {
            node {
              id
              entity_type
              parent_types
              x_opencti_description
              ... on Software {
                name
                version
                vendor
              }
            }
          }
        }
      }
    `,
  },
  {
    direction: 'forward',
    getConnectionFromProps(props) {
      return props.data && props.data.softwares;
    },
    getFragmentVariables(prevVars, totalCount) {
      return {
        ...prevVars,
        count: totalCount,
      };
    },
    getVariables(props, { count, cursor }, fragmentVariables) {
      return {
        search: fragmentVariables.search,
        count,
        cursor,
      };
    },
    query: addSoftwaresLinesQuery,
  },
);

export default compose(inject18n)(AddSoftwaresLines);
