import { graphql, ConnectionHandler, Variables } from 'react-relay';

export const generateConnectionId = ({ recordId, key, params }: { recordId?: string, key: string, params?: Variables }) => ConnectionHandler.getConnectionID(recordId ?? 'root', key, params ?? {});

export const caseSetTemplateQuery = graphql`
  mutation CaseUtilsSetTemplateMutation($id: ID!, $caseTemplatesId: [ID!]!, $connections: [ID!]!) {
    caseSetTemplate(
      id: $id
      caseTemplatesId: $caseTemplatesId
    ) {
      ...CaseUtils_case
      tasks {
        edges {
          node @appendNode(connections: $connections, edgeTypeName: "Task") {
            ...CaseTasksLine_data
          }
        }
      }
    }
  }
`;

export const caseMutationFieldPatch = graphql`
  mutation CaseUtilsFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
  ) {
    stixDomainObjectEdit(id: $id) {
      fieldPatch(input: $input) {
        ...CaseTasksLine_data
        ... on Task {
          objects {
            edges {
              node {
                ...CaseUtils_case
              }
            }
          }
        }      
      }
    }
  }
`;

export const caseEditionOverviewFocus = graphql`
  mutation CaseUtilsFocusMutation($id: ID!, $input: EditContext!) {
    stixDomainObjectEdit(id: $id) {
      contextPatch(input: $input) {
        id
      }
    }
  }
`;

export const caseMutationRelationAdd = graphql`
  mutation CaseUtilsRelationAddMutation(
    $id: ID!
    $input: StixRefRelationshipAddInput!
  ) {
    stixDomainObjectEdit(id: $id) {
      relationAdd(input: $input) {
        from {
          ...CaseUtils_case
        }
      }
    }
  }
`;
export const caseMutationRelationDelete = graphql`
  mutation CaseUtilsRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    stixDomainObjectEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        ...CaseUtils_case
      }
    }
  }
`;

export const caseFragment = graphql`
  fragment CaseUtils_case on Case {
    id
    name
    standard_id
    entity_type
    x_opencti_stix_ids
    created
    modified
    created_at
    revoked
    description
    confidence
    creators {
      id
      name
    }
    createdBy {
      ... on Identity {
        id
        name
        entity_type
      }
    }
    objectMarking {
      edges {
        node {
          id
          definition_type
          definition
          x_opencti_order
          x_opencti_color
        }
      }
    }
    objectLabel {
      edges {
        node {
          id
          value
          color
        }
      }
    }
    objectAssignee {
      edges {
        node {
          id
          name
          entity_type
        }
      }
    }
    objectParticipant {
      edges {
        node {
          id
          name
          entity_type
        }
      }
    }
    x_opencti_stix_ids
    status {
      id
      order
      template {
        name
        color
      }
    }
    workflowEnabled
    ...CaseIncidentDetails_case
    ...FeedbackDetails_case
    ...CaseRftDetails_case
    ...CaseRfiDetails_case
    ...ContainerHeader_container
    ...ContainerStixObjectsOrStixRelationships_container
  }
`;
