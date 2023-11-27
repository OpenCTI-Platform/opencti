import { graphql } from 'react-relay';

export const triggersQueriesKnowledgeSearchQuery = graphql`
  query TriggersQueriesSearchKnowledgeQuery(
    $search: String
    $filters: FilterGroup
    $includeAuthorities: Boolean
  ) {
    triggersKnowledge(search: $search, filters: $filters, includeAuthorities: $includeAuthorities) {
      edges {
        node {
          id
          name
          trigger_type
          event_types
          description
          created
          modified
          notifiers {
            id
          }
        }
      }
    }
  }
`;

export const triggersQueriesActivitySearchQuery = graphql`
  query TriggersQueriesSearchActivityQuery(
    $search: String
    $filters: FilterGroup
  ) {
    triggersActivity(search: $search, filters: $filters) {
      edges {
        node {
          id
          name
          trigger_type
          event_types
          description
          created
          modified
          notifiers {
            id
          }
        }
      }
    }
  }
`;
