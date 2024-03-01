import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer, graphql } from 'react-relay';
import { compose } from 'ramda';
import inject18n from '../../../../components/i18n';
import StixCoreRelationshipCreationFromEntityList from '../../common/stix_core_relationships/StixCoreRelationshipCreationFromEntityList';

export const addSubSectorsMutationRelationDelete = graphql`
  mutation AddSubSectorsLinesRelationDeleteMutation(
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

class AddSubSectorsLinesContainer extends Component {
  render() {
    const { data, sectorSubSectors, sector } = this.props;
    return (
      <StixCoreRelationshipCreationFromEntityList
        entity={sector}
        relationshipType={'part-of'}
        availableDatas={data?.sectors}
        existingDatas={sectorSubSectors}
        updaterOptions={ { path: 'subSectors' } }
        isRelationReversed={true}
      />
    );
  }
}

AddSubSectorsLinesContainer.propTypes = {
  sector: PropTypes.object,
  sectorSubSectors: PropTypes.array,
  data: PropTypes.object,
};

export const addSubSectorsLinesQuery = graphql`
  query AddSubSectorsLinesQuery($search: String, $count: Int, $cursor: ID) {
    ...AddSubSectorsLines_data
      @arguments(search: $search, count: $count, cursor: $cursor)
  }
`;

const AddSubSectorsLines = createPaginationContainer(
  AddSubSectorsLinesContainer,
  {
    data: graphql`
      fragment AddSubSectorsLines_data on Query
      @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
      ) {
        sectors(search: $search, first: $count, after: $cursor)
          @connection(key: "Pagination_sectors") {
          edges {
            types
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
      return props.data && props.data.subSectors;
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
    query: addSubSectorsLinesQuery,
  },
);

export default compose(inject18n)(AddSubSectorsLines);
