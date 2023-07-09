import { graphql } from 'react-relay';

export const triggersQueriesKnowledgeSearchQuery = graphql`
  query TriggersQueriesSearchKnowledgeQuery(
    $search: String
    $filters: [TriggersFiltering!]
  ) {
    triggersKnowledge(search: $search, filters: $filters) {
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

export const triggersQueriesActivitySearchQuery = graphql`
  query TriggersQueriesSearchActivityQuery(
    $search: String
    $filters: [TriggerActivityFiltering!]
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
          outcomes
        }
      }
    }
  }
`;
