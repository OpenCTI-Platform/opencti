import graphql from 'babel-plugin-relay/macro';

// eslint-disable-next-line import/prefer-default-export
export const cyioLabelsQuery = graphql`
  query CyioLabelsQuery($search: String) {
    cyioLabels(search: $search) {
      edges {
        node {
          __typename
          id
          created
          modified
          name
          color
          description
        }
      }
    }
  }
`;
