import { graphql } from 'react-relay';

export const attributesSearchQuery = graphql`
  query AttributesQuerySearchQuery(
    $first: Int
    $search: String
    $attributeName: String!
  ) {
    runtimeAttributes(
      first: $first
      search: $search
      attributeName: $attributeName
    ) {
      edges {
        node {
          id
          value
        }
      }
    }
  }
`;
