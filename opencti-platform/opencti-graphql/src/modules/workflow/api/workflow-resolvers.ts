import { GraphQLError } from 'graphql';
import type { AuthContext } from '../../../types/user';
import { reportWorkflowAsyncActionResult } from '../domain/workflow-async-completion';
import {
    clearWorkflowPendingState,
    deleteWorkflowDefinition,
    getAllowedTransitions,
    getWorkflowDefinition,
    getWorkflowInstance,
    getWorkflowMigrationPreview,
    getWorkflowPublishedVersionId,
    hasPublishedWorkflowDefinition,
    publishWorkflowDefinition,
    restorePublishedWorkflowDefinition,
    setWorkflowDefinition,
    setWorkflowStatus,
    triggerWorkflowEvent,
} from '../domain/workflow-domain';

const COMMENT_MAX_LENGTH = 1000; // Keep in sync with COMMENT_MAX_LENGTH in opencti-front/src/private/components/common/workflow/WorkflowStatus.tsx

const workflowResolvers = {
  Query: {
    workflowDefinition: (_: any, { entityType, allowDraft = false }: { entityType: string; allowDraft?: boolean }, context: AuthContext) => {
      return getWorkflowDefinition(context, context.user!, entityType, allowDraft);
    },
    workflowDefinitionPublished: (_: any, { entityType }: { entityType: string }, context: AuthContext) => {
      return hasPublishedWorkflowDefinition(context, context.user!, entityType);
    },
    workflowMigrationPreview: async (_: any, { entityType }: { entityType: string }, context: AuthContext) => {
      const { byScope } = await getWorkflowMigrationPreview(context, context.user!, entityType);
      return {
        entityType,
        results: Object.entries(byScope).map(([scope, result]) => ({
          scope,
          initialState: result!.definition.initialState,
          states: result!.definition.states,
          transitions: result!.definition.transitions,
          diagnostics: result!.diagnostics,
        })),
      };
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
    workflowDefinitionRestorePublished: (_: any, { entityType }: { entityType: string }, context: AuthContext) => {
      return restorePublishedWorkflowDefinition(context, context.user!, entityType);
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
    setWorkflowStatus: (_: any, {
      entityId,
      targetStatusId,
      applyTransitionActions,
      comment,
    }: { entityId: string; targetStatusId: string; applyTransitionActions: boolean; comment?: string | null }, context: AuthContext) => {
      const normalizedComment = comment?.trim() ?? undefined;
      if (normalizedComment !== undefined && normalizedComment.length > COMMENT_MAX_LENGTH) {
        throw new GraphQLError(`Comment exceeds maximum allowed length of ${COMMENT_MAX_LENGTH} characters.`);
      }
      return setWorkflowStatus(context, context.user!, entityId, targetStatusId, applyTransitionActions, normalizedComment);
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
  WorkflowSerializedTransition: {
    from: (transition: any) => {
      if (transition.from === null || transition.from === undefined) return [];
      return Array.isArray(transition.from) ? transition.from : [transition.from];
    },
    to: (transition: any) => transition.to ?? null,
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
  EntitySetting: {
    workflow_published_version_id: (entitySetting: any, _: any, context: AuthContext) => {
      return getWorkflowPublishedVersionId(context, entitySetting);
    },
  },
  DraftWorkspace: {
    // Task 5, Step 0.7: batched via context.batch.workflowInstancesBatchLoader (see
    // httpAuthenticatedContext.js/computeLoaders) instead of calling getWorkflowInstance directly,
    // so a paginated list of entities embedding this field issues one bulk lookup, not N.
    workflowInstance: (draft: any, _: any, context: AuthContext) => {
      return context.batch.workflowInstancesBatchLoader.load(draft);
    },
  },
  // Task 5, Step 0.3: the only other entity type with a configurable workflow today
  // (see entitySetting-utils.ts's `workflow_id` allow-list).
  StixSightingRelationship: {
    workflowInstance: (relationship: any, _: any, context: AuthContext) => {
      return context.batch.workflowInstancesBatchLoader.load(relationship);
    },
  },
  // Task 9, Step 1: every concrete type implementing the StixDomainObject interface (see the
  // matching `extend type` declarations in workflow.graphql) resolves through the same batch
  // loader — resolves to null until the entity type's EntitySetting.workflow_id references a
  // published WorkflowDefinition (see Task 6's migration).
  ...Object.fromEntries(
    [
      'AttackPattern', 'Campaign', 'Note', 'ObservedData', 'Opinion', 'Report', 'CourseOfAction',
      'Individual', 'Sector', 'System', 'Infrastructure', 'IntrusionSet', 'Position', 'City',
      'Country', 'Region', 'Malware', 'ThreatActorGroup', 'Tool', 'Vulnerability', 'Incident',
      'AdministrativeArea', 'CaseIncident', 'CaseRfi', 'CaseRft', 'Channel', 'DataComponent',
      'DataSource', 'Event', 'Feedback', 'Grouping', 'Indicator', 'Language', 'MalwareAnalysis',
      'Narrative', 'Organization', 'SecurityCoverage', 'SecurityPlatform', 'Task', 'ThreatActorIndividual',
    ].map((typeName) => [typeName, {
      workflowInstance: (entity: any, _: any, context: AuthContext) => context.batch.workflowInstancesBatchLoader.load(entity),
    }]),
  ),
  WorkflowDefinitionMutationResult: {
    errors: (result: any) => result.errors ?? [],
    published: (result: any) => result.published ?? false,
  },
};

export default workflowResolvers;
