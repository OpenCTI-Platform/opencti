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
      closingReason
      requiresShareOrganizationInput
      requiresUnshareOrganizationInput
      requestAccessOutcome
      toStatus {
        id
        order
        template {
          name
          color
        }
      }
    }
    blockedTransitions {
      event
      toState
      blockingConditions
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
    x_opencti_closing_reason
    updated_at
    objectAssignee {
      id
    }
    objectParticipant {
      id
    }
    workflowInstance {
      ...WorkflowStatus_workflowInstance @relay(mask: false)
    }
  }
`;

// A transition can reset the access restriction, and the headers read it from the store: every operation that
// returns the entity after a transition selects it. Kept out of the fragment the entity pages embed, so loading a
// page never resolves members for nothing.
export const workflowStatusAuthorizedMembersFragment = graphql`
  fragment WorkflowStatusAuthorizedMembers_data on StixDomainObject {
    ... on Container {
      authorized_members {
        ...WorkflowStatusMemberAccess_data @relay(mask: false)
      }
    }
    ... on Organization {
      authorized_members {
        ...WorkflowStatusMemberAccess_data @relay(mask: false)
      }
    }
  }
`;

export const workflowStatusMemberAccessFragment = graphql`
  fragment WorkflowStatusMemberAccess_data on MemberAccess {
    id
    member_id
    name
    entity_type
    access_right
    groups_restriction {
      id
      name
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
        ...WorkflowStatus_workflowInstance @relay(mask: false)
      }
      entity {
        ... on DraftWorkspace {
          ...WorkflowStatus_data
          authorizedMembers {
            ...WorkflowStatusMemberAccess_data @relay(mask: false)
          }
        }
        ... on StixDomainObject {
          ...WorkflowStatusStixDomainObject_data
        }
        ...WorkflowStatusAuthorizedMembers_data
      }
    }
  }
`;

export const workflowStatusEntityQuery = graphql`
  query WorkflowStatusEntityQuery($id: String!) {
    stixDomainObject(id: $id) {
      id
      ...WorkflowStatusStixDomainObject_data
      # Polled while a transition with async actions runs: its sync actions (reset authorized members...) run then
      ...WorkflowStatusAuthorizedMembers_data
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
        ...WorkflowStatusAuthorizedMembers_data
      }
    }
  }
`;
