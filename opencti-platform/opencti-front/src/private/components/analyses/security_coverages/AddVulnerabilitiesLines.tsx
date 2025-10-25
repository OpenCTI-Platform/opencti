import React, { FunctionComponent } from 'react';
import { createPaginationContainer, graphql } from 'react-relay';
import StixCoreRelationshipCreationFromEntityList from '../../common/stix_core_relationships/StixCoreRelationshipCreationFromEntityList';

export const addVulnerabilitiesLinesQuery = graphql`
  query AddVulnerabilitiesLinesQuery(
    $search: String
    $count: Int!
    $cursor: ID
  ) {
    ...AddVulnerabilitiesLines_data
      @arguments(search: $search, count: $count, cursor: $cursor)
  }
`;

export interface AddVulnerabilitiesLinesProps {
  securityCoverage: {
    id: string;
  };
  securityCoverageVulnerabilities: Array<{
    node: {
      id: string;
    };
  }>;
  data: {
    vulnerabilities: {
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

const AddVulnerabilitiesLinesContainer: FunctionComponent<AddVulnerabilitiesLinesProps> = ({
  data,
  securityCoverageVulnerabilities,
  securityCoverage,
}) => {
  return (
    <StixCoreRelationshipCreationFromEntityList
      entity={securityCoverage}
      relationshipType="has-covered"
      availableDatas={data?.vulnerabilities}
      existingDatas={securityCoverageVulnerabilities}
      updaterOptions={{
        path: 'vulnerabilities',
        params: {
          relationship_type: 'has-covered',
          toTypes: ['Vulnerability'],
        },
      }}
      isRelationReversed={false}
    />
  );
};

const AddVulnerabilitiesLines = createPaginationContainer(
  AddVulnerabilitiesLinesContainer,
  {
    data: graphql`
      fragment AddVulnerabilitiesLines_data on Query
      @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
      ) {
        vulnerabilities(search: $search, first: $count, after: $cursor)
          @connection(key: "Pagination_vulnerabilities") {
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
      return props.data && props.data.vulnerabilities;
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
    query: addVulnerabilitiesLinesQuery,
  },
);

export default AddVulnerabilitiesLines;
