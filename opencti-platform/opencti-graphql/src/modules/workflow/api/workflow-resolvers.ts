import { GraphQLError } from 'graphql';
import type { AuthContext } from '../../../types/user';
import {
  deleteWorkflowDefinition,
  getAllowedNextStatuses,
  getAllowedTransitions,
  getWorkflowDefinition,
  getWorkflowInstance,
  setWorkflowDefinition,
  triggerWorkflowEvent,
} from '../domain/workflow-domain';

const COMMENT_MAX_LENGTH = 1000; // Keep in sync with COMMENT_MAX_LENGTH in opencti-front/src/private/components/common/workflow/WorkflowStatus.tsx

const workflowResolvers = {
  Query: {
    workflowDefinition: (_: any, { entityType }: { entityType: string }, context: AuthContext) => {
      return getWorkflowDefinition(context, context.user!, entityType);
    },
    workflowInstance: (_: any, { entityId }: { entityId: string }, context: AuthContext) => {
      // Logic for resolving workflowInstance
      return getWorkflowInstance(context, context.user!, entityId);
    },
    allowedNextStatuses: (_: any, { entityId }: { entityId: string }, context: AuthContext) => {
      return getAllowedNextStatuses(context, context.user!, entityId);
    },
    allowedTransitions: (_: any, { entityId }: { entityId: string }, context: AuthContext) => {
      return getAllowedTransitions(context, context.user!, entityId);
    },
  },
  Mutation: {
    workflowDefinitionSet: (_: any, { entityType, definition }: { entityType: string; definition: string }, context: AuthContext) => {
      return setWorkflowDefinition(context, context.user!, entityType, definition);
    },
    workflowDefinitionDelete: (_: any, { entityType }: { entityType: string }, context: AuthContext) => {
      return deleteWorkflowDefinition(context, context.user!, entityType);
    },
    triggerWorkflowEvent: (_: any, { entityId, eventName, comment }: { entityId: string; eventName: string; comment?: string | null }, context: AuthContext) => {
      const normalizedComment = comment?.trim() ?? undefined;
      if (normalizedComment !== undefined && normalizedComment.length > COMMENT_MAX_LENGTH) {
        throw new GraphQLError(`Comment exceeds maximum allowed length of ${COMMENT_MAX_LENGTH} characters.`);
      }
      return triggerWorkflowEvent(context, context.user!, entityId, eventName, normalizedComment);
    },
  },
  WorkflowInstance: {
    id: (instance: any) => instance.id || instance.internal_id,
    currentState: (instance: any) => instance.currentState,
    currentStatus: (instance: any) => ({ id: instance.currentState, template_id: instance.currentState }),
    allowedTransitions: (instance: any) => instance.allowedTransitions,
    lastHistoryEntry: (instance: any) => {
      const history: Array<{ state: string; event: string; user_id: string; timestamp: string; comment?: string | null }> = instance.history ?? [];
      return history.length > 0 ? history[history.length - 1] : null;
    },
  },
  WorkflowTransition: {
    toStatus: (transition: any) => ({ id: transition.toState, template_id: transition.toState }),
    comment: (transition: any) => transition.comment ?? null,
    actions: (transition: any) => transition.actions ?? [],
  },
  WorkflowTriggerResult: {
    status: (result: any) => (result.newState ? { id: result.newState, template_id: result.newState } : null),
    instance: (result: any) => result.instance,
    entity: (result: any) => result.entity,
  },
  DraftWorkspace: {
    workflowInstance: (draft: any, _: any, context: AuthContext) => {
      const draftId = draft.id || draft.internal_id;
      return getWorkflowInstance(context, context.user!, draftId);
    },
  },
};

export default workflowResolvers;
