import { graphql } from 'react-relay';

// eslint-disable-next-line import/prefer-default-export
export const incidentLineFragment = graphql`
  fragment IncidentLine_node on Incident {
    id
    name
    incident_type
    severity
    created
    modified
    confidence
    entity_type
    objectAssignee {
      entity_type
      id
      name
    }
    objectMarking {
      id
      definition_type
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
    status {
      id
      order
      template {
        name
        color
      }
    }
    workflowEnabled
  }
`;
