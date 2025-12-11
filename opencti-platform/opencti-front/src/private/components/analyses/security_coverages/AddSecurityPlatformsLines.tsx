import React, { FunctionComponent } from 'react';
import { createPaginationContainer, graphql } from 'react-relay';
import StixCoreRelationshipCreationFromEntityList from '../../common/stix_core_relationships/StixCoreRelationshipCreationFromEntityList';

export const addSecurityPlatformsLinesQuery = graphql`
  query AddSecurityPlatformsLinesQuery(
    $search: String
    $count: Int!
    $cursor: ID
  ) {
    ...AddSecurityPlatformsLines_data
      @arguments(search: $search, count: $count, cursor: $cursor)
  }
`;

export interface AddSecurityPlatformsLinesProps {
  securityCoverage: {
    id: string;
  };
  securityCoverageSecurityPlatforms: Array<{
    node: {
      id: string;
    };
  }>;
  data: {
    securityPlatforms: {
      edges: Array<{
        node: {
          id: string;
          entity_type: string;
          parent_types: string[];
          name: string;
          description?: string;
        };
      }>;
    };
  } | null;
}

const AddSecurityPlatformsLinesContainer: FunctionComponent<AddSecurityPlatformsLinesProps> = ({
  data,
  securityCoverageSecurityPlatforms,
  securityCoverage,
}) => {
  return (
    <StixCoreRelationshipCreationFromEntityList
      entity={securityCoverage}
      relationshipType="has-covered"
      availableDatas={data?.securityPlatforms}
      existingDatas={securityCoverageSecurityPlatforms}
      updaterOptions={{
        path: 'securityPlatforms',
        params: {
          relationship_type: 'has-covered',
          toTypes: ['SecurityPlatform'],
        },
      }}
      isRelationReversed={false}
    />
  );
};

const AddSecurityPlatformsLines = createPaginationContainer(
  AddSecurityPlatformsLinesContainer,
  {
    data: graphql`
      fragment AddSecurityPlatformsLines_data on Query
      @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
      ) {
        securityPlatforms(search: $search, first: $count, after: $cursor)
          @connection(key: "Pagination_securityPlatforms") {
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
      return props.data && props.data.securityPlatforms;
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
        search: fragmentVariables.search,
      };
    },
    query: addSecurityPlatformsLinesQuery,
  },
);

export default AddSecurityPlatformsLines;
