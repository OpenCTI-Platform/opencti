import graphql from 'babel-plugin-relay/macro';

// eslint-disable-next-line import/prefer-default-export
export const RiskFiltersQuery = graphql`
  query RiskFiltersQuery(
    $type: String!
  ) {
    __type(name: $type ) {
      name
      enumValues {
        name
        description
      }
    }
  }
`;

export const riskFiltersNameQuery = graphql`
  query RiskFiltersNameQuery(
    $search: String
  ) {
    risks(search: $search) {
      edges {
        node {
          name
        }
      }
    }
  }
`;
