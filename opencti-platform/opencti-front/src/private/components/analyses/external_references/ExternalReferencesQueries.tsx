import { graphql } from 'react-relay';

export const externalReferencesQueriesSearchQuery = graphql`
  query ExternalReferencesQueriesSearchQuery(
    $search: String
    $filters: FilterGroup
  ) {
    externalReferences(search: $search, filters: $filters) {
      edges {
        node {
          id
          entity_type
          source_name
          external_id
          description
          url
          fileId
        }
      }
    }
  }
`;
