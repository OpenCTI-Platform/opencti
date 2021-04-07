import graphql from 'babel-plugin-relay/macro';

// eslint-disable-next-line import/prefer-default-export
export const attributesSearchQuery = graphql`
  query AttributesQuerySearchQuery(
    $key: String
    $elementType: String
    $fieldKey: String
    $search: String
    $first: Int
  ) {
    attributes(
      key: $key
      elementType: $elementType
      fieldKey: $fieldKey
      search: $search
      first: $first
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
