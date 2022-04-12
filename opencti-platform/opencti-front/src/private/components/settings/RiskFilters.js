import graphql from 'babel-plugin-relay/macro';

// eslint-disable-next-line import/prefer-default-export
export const RiskFiltersFieldsQuery = graphql`
  query RiskFiltersFieldsQuery(
    $search: String
  ) {
    poamItems(search: $search) {
      edges {
        node {
          related_risks {
            edges {
              node {
                __typename
                id
                name
                risk_status
                risk_level
                deadline
                remediations {
                  id
                  response_type
                  lifecycle
                }
              }
            }
          }
        }
      }
    }
  }
`;
