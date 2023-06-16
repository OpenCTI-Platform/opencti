import { graphql } from 'react-relay';

// eslint-disable-next-line import/prefer-default-export
export const triggersQueriesSearchQuery = graphql`
  query TriggersQueriesSearchQuery(
    $search: String
    $filters: [TriggersFiltering!]
  ) {
    triggers(search: $search, filters: $filters) {
      edges {
        node {
          id
          name
          trigger_type
          event_types
          description
          created
          modified
          outcomes
        }
      }
    }
  }
`;
