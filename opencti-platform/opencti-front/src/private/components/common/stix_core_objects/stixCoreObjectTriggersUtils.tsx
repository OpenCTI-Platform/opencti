import { graphql } from 'react-relay';

export const stixCoreObjectTriggersFragment = graphql`
  fragment stixCoreObjectTriggersUtils_triggers on Query @refetchable(queryName: "stixCoreObjectTriggersUtils_triggersRefetch") {
    triggersKnowledgeCount(filters: $filters, includeAuthorities: $includeAuthorities)
    triggersKnowledge(after: $after, filters: $filters, first: $first, includeAuthorities: $includeAuthorities)
    @connection(key: "Pagination_quickSubscription__triggersKnowledge") {
      edges {
        node {
          id
          name
          trigger_type
          event_types
          description
          filters
          created
          modified
          notifiers {
            id
            name
          }
          recipients {
            name
            id
            entity_type
          }
        }
      }
    }
  }
`;

export const stixCoreObjectQuickSubscriptionContentQuery = graphql`
  query stixCoreObjectTriggersUtilsPaginationQuery(
    $filters: FilterGroup
    $first: Int
    $includeAuthorities: Boolean
    $after: ID
  ) {
    ...stixCoreObjectTriggersUtils_triggers
  }
`;
