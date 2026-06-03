import { GraphQLError } from 'graphql';
import type { AuthContext } from '../../../types/user';
import { reportWorkflowAsyncActionResult } from '../domain/workflow-async-completion';
import {
  clearWorkflowPendingState,
  deleteWorkflowDefinition,
  getAllowedTransitions,
  getWorkflowDefinition,
  getWorkflowInstance,
  publishWorkflowDefinition,
  setWorkflowDefinition,
  triggerWorkflowEvent,
} from '../domain/workflow-domain';

const COMMENT_MAX_LENGTH = 1000; // Keep in sync with COMMENT_MAX_LENGTH in opencti-front/src/private/components/common/workflow/WorkflowStatus.tsx

const workflowResolvers = {
  Query: {
    workflowDefinition: (_: any, { entityType, allowDraft = false }: { entityType: string; allowDraft?: boolean }, context: AuthContext) => {
      return getWorkflowDefinition(context, context.user!, entityType, allowDraft);
    },
    workflowInstance: (_: any, { entityId }: { entityId: string }, context: AuthContext) => {
      return getWorkflowInstance(context, context.user!, entityId);
    },
    allowedTransitions: (_: any, { entityId }: { entityId: string }, context: AuthContext) => {
      return getAllowedTransitions(context, context.user!, entityId);
    },
  },
  Mutation: {
    workflowDefinitionSet: (_: any, { entityType, definition }: { entityType: string; definition: string }, context: AuthContext) => {
      return setWorkflowDefinition(context, context.user!, entityType, definition);
    },
    workflowDefinitionPublish: (_: any, { entityType }: { entityType: string }, context: AuthContext) => {
      return publishWorkflowDefinition(context, context.user!, entityType);
    },
    workflowDefinitionDelete: (_: any, { entityType }: { entityType: string }, context: AuthContext) => {
      return deleteWorkflowDefinition(context, context.user!, entityType);
    },
    triggerWorkflowEvent: (_: any, {
      entityId,
      eventName,
      comment,
      runtimeParams,
    }: { entityId: string; eventName: string; comment?: string | null; runtimeParams?: Record<string, unknown> }, context: AuthContext) => {
      const normalizedComment = comment?.trim() ?? undefined;
      if (normalizedComment !== undefined && normalizedComment.length > COMMENT_MAX_LENGTH) {
        throw new GraphQLError(`Comment exceeds maximum allowed length of ${COMMENT_MAX_LENGTH} characters.`);
      }
      return triggerWorkflowEvent(context, context.user!, entityId, eventName, normalizedComment, runtimeParams ?? {});
    },
    clearWorkflowPendingState: (_: any, { entityId }: { entityId: string }, context: AuthContext) => {
      return clearWorkflowPendingState(context, context.user!, entityId);
    },
    reportWorkflowAsyncActionResult: async (_: any, args: { workflowInstanceId: string; workflowActionId: string; status: string; error?: string }, context: AuthContext) => {
      await reportWorkflowAsyncActionResult(
        context,
        context.user!,
        args.workflowInstanceId,
        args.workflowActionId,
        args.status as 'success' | 'failed',
        args.error,
      );
      return true;
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
    pendingStatus: (instance: any) => instance.pendingStatus ?? null,
    pendingError: (instance: any) => instance.pendingError ?? null,
    pendingTransition: (instance: any) => instance.pendingTransition ?? null,
  },
  WorkflowTransition: {
    toStatus: (transition: any) => ({ id: transition.toState, template_id: transition.toState }),
    comment: (transition: any) => transition.comment ?? null,
    actions: (transition: any) => transition.actions ?? [],
    requiresShareOrganizationInput: (transition: any) => transition.requiresShareOrganizationInput ?? false,
    requiresUnshareOrganizationInput: (transition: any) => transition.requiresUnshareOrganizationInput ?? false,
  },
  WorkflowPendingAsyncAction: {
    id: (slot: any) => slot.id,
    workId: (slot: any) => slot.workId,
    type: (slot: any) => slot.type,
    status: (slot: any) => slot.status,
    processedCount: (slot: any) => slot.processedCount ?? null,
    expectedCount: (slot: any) => slot.expectedCount ?? null,
    startedAt: (slot: any) => slot.startedAt ?? null,
    lastActivityAt: (slot: any) => slot.lastActivityAt ?? null,
    errors: (slot: any) => slot.errors ?? [],
  },
  WorkflowPendingTransition: {
    event: (pt: any) => pt.event,
    toState: (pt: any) => pt.toState,
    triggeredAt: (pt: any) => pt.triggeredAt,
    asyncActions: (pt: any) => pt.asyncActions ?? [],
  },
  WorkflowTriggerResult: {
    status: (result: any) => (result.newState ? { id: result.newState, template_id: result.newState } : null),
    instance: (result: any) => result.instance,
    entity: (result: any) => result.entity,
    executionStatus: (result: any) => result.executionStatus ?? null,
    pendingTransition: (result: any) => result.instance?.pendingTransition ?? null,
  },
  DraftWorkspace: {
    workflowInstance: (draft: any, _: any, context: AuthContext) => {
      const draftId = draft.id || draft.internal_id;
      return getWorkflowInstance(context, context.user!, draftId);
    },
  },
  WorkflowDefinitionMutationResult: {
    errors: (result: any) => result.errors ?? [],
    published: (result: any) => result.published ?? false,
  },
};

export default workflowResolvers;
