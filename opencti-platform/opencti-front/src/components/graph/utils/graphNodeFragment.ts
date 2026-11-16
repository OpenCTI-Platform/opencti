import { graphql } from 'react-relay';

// What the graph needs to draw an object as a node: its representative, plus the fields
// giving its date in the time range, the details of observables and the color of meta objects.
// Meant to be spread unmasked (@relay(mask: false)) in queries whose results are handed
// to the graph as plain objects, like the investigation expands.
export const graphNodeFragment = graphql`
  fragment graphNodeFragment_node on StixObject {
    id
    standard_id
    entity_type
    parent_types
    representative {
      main
    }
    ... on StixCoreObject {
      is_inferred
      created_at
      numberOfConnectedElement
      createdBy {
        ... on Identity {
          id
          name
          entity_type
        }
      }
      objectMarking {
        id
        definition_type
        definition
        x_opencti_order
        x_opencti_color
      }
    }
    ... on StixDomainObject {
      created
      confidence
    }
    ... on Campaign {
      first_seen
    }
    ... on IntrusionSet {
      first_seen
    }
    ... on Malware {
      first_seen
    }
    ... on ThreatActor {
      first_seen
    }
    ... on Incident {
      first_seen
    }
    ... on Indicator {
      valid_from
    }
    ... on Report {
      published
    }
    ... on ObservedData {
      first_observed
    }
    ... on StixCyberObservable {
      observable_value
    }
    ... on StixFile {
      observableName: name
      hashes {
        algorithm
        hash
      }
    }
    ... on StixMetaObject {
      created
    }
    ... on Label {
      color
    }
    ... on MarkingDefinition {
      definition
      x_opencti_color
    }
  }
`;
