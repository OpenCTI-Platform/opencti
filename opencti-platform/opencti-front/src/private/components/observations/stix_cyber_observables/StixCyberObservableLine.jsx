import { graphql } from 'react-relay';

export const stixCyberObservableLineFragment = graphql`
  fragment StixCyberObservableLine_node on StixCyberObservable {
    id
    entity_type
    parent_types
    observable_value
    created_at
    draftVersion {
      draft_id
      draft_operation
    }
    createdBy {
      ... on Identity {
        id
        name
        entity_type
      }
    }
    ... on IPv4Addr {
      countries {
        edges {
          node {
            name
            x_opencti_aliases
          }
        }
      }
    }
    ... on IPv6Addr {
      countries {
        edges {
          node {
            name
            x_opencti_aliases
          }
        }
      }
    }
    objectMarking {
      id
      definition
      x_opencti_order
      x_opencti_color
    }
    objectLabel {
      id
      value
      color
    }
    creators {
      id
      name
    }
  }
`;
