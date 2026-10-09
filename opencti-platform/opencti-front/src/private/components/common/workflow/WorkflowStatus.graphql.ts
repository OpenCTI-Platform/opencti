import { graphql } from 'react-relay';

// Keep in sync with COMMENT_MAX_LENGTH in opencti-graphql/src/modules/workflow/types/workflow-types.ts
export const COMMENT_MAX_LENGTH = 1000;

export const workflowStatusWorkflowInstanceFragment = graphql`
  fragment WorkflowStatus_workflowInstance on WorkflowInstance {
    id
    currentState
    currentStatus {
      id
      order
      template {
        name
        color
      }
    }
    lastHistoryEntry {
      comment
      timestamp
    }
    pendingStatus
    pendingError
    pendingTransition {
      event
      toState
      triggeredAt
      syncActions {
        type
      }
      asyncActions {
        id
        type
        status
        processedCount
        expectedCount
        errors {
          message
        }
      }
    }
    allowedTransitions {
      event
      toState
      actions
      comment
      requiresShareOrganizationInput
      requiresUnshareOrganizationInput
      toStatus {
        id
        order
        template {
          name
          color
        }
      }
    }
  }
`;

export const workflowStatusFragment = graphql`
  fragment WorkflowStatus_data on DraftWorkspace {
    id
    entity_id
    processingCount
    workflowInstance {
      ...WorkflowStatus_workflowInstance @relay(mask: false)
    }
  }
`;

export const workflowStatusStixDomainObjectFragment = graphql`
  fragment WorkflowStatusStixDomainObject_data on StixDomainObject {
    id
    entity_type
    currentUserAccessRight
    workflowInstance {
      ...WorkflowStatus_workflowInstance @relay(mask: false)
    }
  }
`;

export const workflowStatusTriggerMutation = graphql`
  mutation WorkflowStatusTriggerMutation($entityId: String!, $eventName: String!, $comment: String, $runtimeParams: JSON) {
    triggerWorkflowEvent(entityId: $entityId, eventName: $eventName, comment: $comment, runtimeParams: $runtimeParams) {
      success
      reason
      newState
      executionStatus
      instance {
        ...WorkflowStatus_workflowInstance @relay(mask: false)
      }
      entity {
        ... on DraftWorkspace {
          ...WorkflowStatus_data
        }
        ... on StixDomainObject {
          ...WorkflowStatusStixDomainObject_data
        }
      }
    }
  }
`;

export const workflowStatusEntityQuery = graphql`
  query WorkflowStatusEntityQuery($id: String!) {
    stixDomainObject(id: $id) {
      id
      ...WorkflowStatusStixDomainObject_data
      status {
        id
        order
        template {
          id
          name
          color
        }
      }
    }
  }
`;

export const workflowStatusClearMutation = graphql`
  mutation WorkflowStatusClearMutation($entityId: String!) {
    clearWorkflowPendingState(entityId: $entityId) {
      id
      pendingStatus
      pendingError
      pendingTransition {
        event
        toState
        triggeredAt
        asyncActions {
          id
          type
          status
          processedCount
          expectedCount
          errors {
            message
          }
        }
      }
    }
  }
`;

export const workflowBypassStatusesQuery = graphql`
  query WorkflowStatusBypassStatusesQuery($entityId: String!) {
    workflowBypassStatuses(entityId: $entityId) {
      onExit {
        type
        params
      }
      onEnter {
        type
        params
      }
      status {
        id
        order
        template {
          name
          color
        }
      }
      requiresShareOrganizationInput
      requiresUnshareOrganizationInput
    }
  }
`;

export const workflowSetStatusMutation = graphql`
  mutation WorkflowStatusSetStatusMutation($entityId: String!, $targetStatusId: String!, $applyTransitionActions: Boolean!, $comment: String, $runtimeParams: JSON) {
    setWorkflowStatus(entityId: $entityId, targetStatusId: $targetStatusId, applyTransitionActions: $applyTransitionActions, comment: $comment, runtimeParams: $runtimeParams) {
      success
      reason
      newState
      executionStatus
      instance {
        ...WorkflowStatus_workflowInstance @relay(mask: false)
      }
      entity {
        ... on StixDomainObject {
          ...WorkflowStatusStixDomainObject_data
        }
      }
    }
  }
`;
