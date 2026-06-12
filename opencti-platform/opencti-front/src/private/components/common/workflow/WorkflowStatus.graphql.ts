import { graphql } from 'react-relay';

// Keep in sync with COMMENT_MAX_LENGTH in opencti-graphql/src/modules/workflow/api/workflow-resolvers.ts
export const COMMENT_MAX_LENGTH = 1000;

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
        template {
          name
          color
        }
      }
      lastHistoryEntry {
        comment
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
  mutation WorkflowStatusTriggerMutation($entityId: String!, $eventName: String!, $comment: String, $runtimeParams: JSON) {
    triggerWorkflowEvent(entityId: $entityId, eventName: $eventName, comment: $comment, runtimeParams: $runtimeParams) {
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
          requiresShareOrganizationInput
          requiresUnshareOrganizationInput
          toStatus {
            id
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
