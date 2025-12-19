import { graphql } from 'react-relay';

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
    draftVersion {
      draft_id
      draft_operation
    }
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
