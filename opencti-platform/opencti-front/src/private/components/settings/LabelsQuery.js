import graphql from 'babel-plugin-relay/macro';

// eslint-disable-next-line import/prefer-default-export
export const labelsSearchQuery = graphql`
  query LabelsQuerySearchQuery($search: String) {
    labels(search: $search) {
      edges {
        node {
          id
          value
          color
        }
      }
    }
  }
`;
