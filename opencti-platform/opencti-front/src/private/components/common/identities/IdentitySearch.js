import { graphql } from 'react-relay';

export const identitySearchIdentitiesSearchQuery = graphql`
  query IdentitySearchIdentitiesSearchQuery(
    $types: [String]
    $search: String
    $first: Int
  ) {
    identities(types: $types, orderBy: _score, orderMode: desc, search: $search, first: $first) {
      edges {
        node {
          id
          standard_id
          identity_class
          name
          entity_type
          ... on Individual {
            isUser
          }
        }
      }
    }
  }
`;

export const identitySearchCreatorsSearchQuery = graphql`
  query IdentitySearchCreatorsSearchQuery($entityTypes: [String!]) {
    creators(entityTypes: $entityTypes) {
      edges {
        node {
          id
          name
        }
      }
    }
    me {
      id
      entity_type
      name
    }
  }
`;
