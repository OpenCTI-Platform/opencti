import graphql from 'babel-plugin-relay/macro';

// eslint-disable-next-line import/prefer-default-export
export const labelsSearchQuery = graphql`
  query LabelsQuerySearchQuery($search: String) {
    cyioLabels(search: $search) {
      pageInfo {
        globalCount
      }
      edges {
        node {
          id
          name
          description
        }
      }
    }
  }
`;
