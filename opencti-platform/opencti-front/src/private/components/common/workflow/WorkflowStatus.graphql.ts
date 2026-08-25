import { graphql } from 'react-relay';

// Keep in sync with COMMENT_MAX_LENGTH in opencti-graphql/src/modules/workflow/api/workflow-resolvers.ts
export const COMMENT_MAX_LENGTH = 1000;

// Keep in sync with CLOSING_REASON_MAX_LENGTH in opencti-graphql/src/modules/workflow/api/workflow-resolvers.ts
export const CLOSING_REASON_MAX_LENGTH = 1000;

export const workflowStatusFragment = graphql`
  fragment WorkflowStatus_data on DraftWorkspace {
    id
    entity_id
    processingCount
    workflowInstance {
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
        closing_reason
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
        isClosingTransition
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
  }
`;

// Task 9, Step 1: generic counterpart of WorkflowStatus_data for any StixDomainObject (Report,
// Malware, Incident, etc.) — DraftWorkspace does not implement the StixDomainObject interface, so
// a single shared fragment isn't possible; this mirrors the exact same workflowInstance shape.
export const workflowStatusStixDomainObjectFragment = graphql`
  fragment WorkflowStatusStixDomainObject_data on StixDomainObject {
    id
    entity_type
    workflowInstance {
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
        closing_reason
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
        isClosingTransition
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
  }
`;

export const workflowStatusTriggerMutation = graphql`
  mutation WorkflowStatusTriggerMutation($entityId: String!, $eventName: String!, $comment: String, $runtimeParams: JSON, $closingReason: String) {
    triggerWorkflowEvent(entityId: $entityId, eventName: $eventName, comment: $comment, runtimeParams: $runtimeParams, closingReason: $closingReason) {
      success
      reason
      newState
      executionStatus
      instance {
        id
        currentState
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
        currentStatus {
          id
          order
          template {
            name
            color
          }
        }
        allowedTransitions {
          event
          toState
          actions
          comment
          isClosingTransition
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
        lastHistoryEntry {
          timestamp
        }
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

// Task 9, Step 3: bypass-update — jumps directly to targetStatusId, bypassing allowedTransitions.
export const workflowSetStatusMutation = graphql`
  mutation WorkflowSetStatusMutation($entityId: String!, $targetStatusId: String!, $applyTransitionActions: Boolean!, $comment: String, $closingReason: String) {
    setWorkflowStatus(entityId: $entityId, targetStatusId: $targetStatusId, applyTransitionActions: $applyTransitionActions, comment: $comment, closingReason: $closingReason) {
      success
      reason
      newState
      executionStatus
      instance {
        id
        currentState
        pendingStatus
        pendingError
        currentStatus {
          id
          order
          template {
            name
            color
          }
        }
        allowedTransitions {
          event
          toState
          actions
          comment
          isClosingTransition
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

