import { logApp } from '../../../config/conf';
import { draftWorkspaceEditAuthorizedMembers, validateDraftWorkspace } from '../../draftWorkspace/draftWorkspace-domain';
import type { AsyncActionSlot, Context } from '../types/workflow-types';
import { generateInternalId } from '../../../schema/identifier';
import { z } from 'zod';
import { editAuthorizedMembers } from '../../../utils/authorizedMembers';
import type { MemberAccessInput } from '../../../generated/graphql';
import { isInternalUser, KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS } from '../../../utils/access';
import { RELATION_CREATED_BY, RELATION_GRANTED_TO, RELATION_OBJECT_ASSIGNEE, RELATION_OBJECT_PARTICIPANT } from '../../../schema/stixRefRelationship';
import { addOrganizationRestriction, createSharingTask, removeOrganizationRestriction } from '../../../domain/stix';
import { buildRefRelationKey } from '../../../schema/general';
import { controlUserConfidenceAgainstElement } from '../../../utils/confidence-level';
import { internalLoadById } from '../../../database/middleware-loader';
import { ENTITY_TYPE_CONTAINER_CASE_RFI } from '../../case/case-rfi/case-rfi-types';
import { UnsupportedError } from '../../../config/errors';

/**
 * Resolves dynamic authorized member keys (AUTHOR, CREATORS, ASSIGNEES, PARTICIPANTS)
 */
const resolveDynamicAuthorizedMembers = (
  entity: any,
  rawMembers: Array<{ id: string; access_right: string; groups_restriction_ids?: string[] }>,
): MemberAccessInput[] => {
  const resolved: MemberAccessInput[] = [];
  for (const member of rawMembers) {
    const { id, access_right, groups_restriction_ids } = member;
    if (id === 'AUTHOR') {
      // AUTHOR resolves to the STIX author of the draft (the createdBy entity, typically an Organization).
      const createdByRef = entity[RELATION_CREATED_BY];
      const createdByIds: string[] = Array.isArray(createdByRef)
        ? createdByRef
        : (createdByRef ? [createdByRef] : []);
      for (const authorId of createdByIds) {
        if (authorId) resolved.push({ id: authorId, access_right, groups_restriction_ids });
      }
    } else if (id === 'CREATORS') {
      const creatorIds: string[] = Array.isArray(entity.creator_id)
        ? entity.creator_id
        : (entity.creator_id ? [entity.creator_id] : []);
      for (const creatorId of creatorIds) {
        if (creatorId) resolved.push({ id: creatorId, access_right, groups_restriction_ids });
      }
    } else if (id === 'ASSIGNEES') {
      const assigneeIds: string[] = Array.isArray(entity[RELATION_OBJECT_ASSIGNEE])
        ? entity[RELATION_OBJECT_ASSIGNEE]
        : (entity[RELATION_OBJECT_ASSIGNEE] ? [entity[RELATION_OBJECT_ASSIGNEE]] : []);
      for (const assigneeId of assigneeIds) {
        if (assigneeId) resolved.push({ id: assigneeId, access_right, groups_restriction_ids });
      }
    } else if (id === 'PARTICIPANTS') {
      const participantIds: string[] = Array.isArray(entity[RELATION_OBJECT_PARTICIPANT])
        ? entity[RELATION_OBJECT_PARTICIPANT]
        : (entity[RELATION_OBJECT_PARTICIPANT] ? [entity[RELATION_OBJECT_PARTICIPANT]] : []);
      for (const participantId of participantIds) {
        if (participantId) resolved.push({ id: participantId, access_right, groups_restriction_ids });
      }
    } else {
      resolved.push({ id, access_right, groups_restriction_ids });
    }
  }
  return resolved;
};

export type ActionFunction<TContext extends Context = Context> = (executionContext: TContext, params?: any) => Promise<void> | void;

export interface ActionDefinition {
  fn: ActionFunction;
  paramsSchema?: z.ZodTypeAny;
  /** Execution positions this action type is allowed in. Omit to allow both. */
  allowedModes?: ('sync' | 'async')[];
}

// Zod schema for an individual background task action step (mirrors BackgroundTask actions[])
const bulkTaskActionSchema = z.object({
  type: z.string(),
  context: z.record(z.string(), z.unknown()).optional(),
});

export const asyncBulkActionParamsSchema = z.object({
  scope: z.string(),
  description: z.string().optional(),
  actions: z.array(bulkTaskActionSchema).min(1),
  failOnAnyError: z.boolean().optional(),
});

export const ActionRegistry: Record<string, ActionFunction> = {
  // actions examples:
  log: async (executionContext, params) => {
    logApp.info(`[Action: LOG] Context: ${JSON.stringify(executionContext)} | Message: ${params?.message || 'No message'}`);
  },
  validateDraft: async (executionContext) => {
    const { entity, user, context } = executionContext;
    await validateDraftWorkspace(context, user, entity.id);
  },
  updateAuthorizedMembers: async (executionContext, params) => {
    const { entity, context, user } = executionContext;
    const rawMembers: Array<{ id: string; access_right: string; groups_restriction_ids?: string[] }> = params?.authorized_members ?? [];
    const resolvedMembers = resolveDynamicAuthorizedMembers(entity, rawMembers);

    if (entity?.entity_type === 'DraftWorkspace') {
      await draftWorkspaceEditAuthorizedMembers(context, user, entity.id, resolvedMembers, { skipAdminValidation: true });
    } else {
      await editAuthorizedMembers(context, user, {
        entityId: entity.id ?? entity.internal_id,
        input: resolvedMembers,
        requiredCapabilities: [KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS],
        entityType: entity.entity_type,
        skipAdminValidation: true,
      });
    }
  },
  shareRequestedEntities: async (executionContext, params) => {
    const { entity, context } = executionContext;
    // Actions run as the workflow manager; sharing must use the rights of the user who fired the transition.
    const user = (executionContext as any).triggeringUser;
    if (!user || isInternalUser(user)) {
      throw UnsupportedError('shareRequestedEntities requires the user who decided the request', { id: entity?.id });
    }
    if (entity?.entity_type !== ENTITY_TYPE_CONTAINER_CASE_RFI || !entity.x_opencti_request_access) {
      throw UnsupportedError('shareRequestedEntities is only available on request access RFIs', { id: entity?.id });
    }
    let requestAccess: { entities?: unknown; members?: unknown } | undefined;
    try {
      requestAccess = JSON.parse(entity.x_opencti_request_access);
    } catch {
      requestAccess = undefined;
    }
    if (!requestAccess || typeof requestAccess !== 'object' || !Array.isArray(requestAccess.entities)) {
      throw UnsupportedError('This RFI is not compatible', { id: entity.id });
    }
    const requestedEntityIds = requestAccess.entities as string[];
    // AUTHOR is the requesting organization recorded on the request at creation, which only the workflow can write.
    // The RFI author is not used: any editor of the RFI can change it, and with it who receives the entities.
    // Only the first member is the organization validated at creation and named on the RFI, as the legacy approval shares.
    const requestedOrganizations: string[] = params?.organizations ?? [];
    const requestingOrganizations = requestedOrganizations.includes('AUTHOR') && Array.isArray(requestAccess.members)
      ? (requestAccess.members as unknown[]).slice(0, 1).filter((member): member is string => typeof member === 'string' && member.length > 0)
      : [];
    // Other keys reuse the dynamic key resolution of authorized members; the access right is irrelevant here.
    const resolvedOrganizationIds = resolveDynamicAuthorizedMembers(
      entity,
      requestedOrganizations.filter((id) => id !== 'AUTHOR').map((id: string) => ({ id, access_right: 'view' })),
    ).map((member) => member.id);
    const organizationIds = [...new Set([...requestingOrganizations, ...resolvedOrganizationIds])];
    if (requestedEntityIds.length === 0 || organizationIds.length === 0) {
      throw UnsupportedError('Nothing to share: no requested entity or no organization resolved', { id: entity.id });
    }
    // Loaded lazily: the schema module pulls the attribute definitions, which the registry does not need otherwise
    const { isStixDomainObjectShareableContainer } = await import('../../../schema/stixDomainObject');
    // Every target is checked against the sharing requirements before the first share, so a refused target leaves nothing shared.
    const targets: { id: string; isContainer: boolean; newOrganizationIds: string[] }[] = [];
    for (const targetId of requestedEntityIds) {
      const target = await internalLoadById<any>(context, user, targetId);
      if (!target) {
        throw UnsupportedError('You cant share the requested element (restrictions or markings)', { targetId });
      }
      if (target.restricted_members?.length) {
        throw UnsupportedError('Element is not sharable at the moment (restricted)', { targetId });
      }
      // The sharing write enforces the confidence of the approver over the target
      controlUserConfidenceAgainstElement(user, target);
      const currentGrants: string[] = target[buildRefRelationKey(RELATION_GRANTED_TO)] ?? [];
      targets.push({
        id: targetId,
        isContainer: isStixDomainObjectShareableContainer(target.entity_type),
        newOrganizationIds: organizationIds.filter((organizationId) => !currentGrants.includes(organizationId)),
      });
    }
    // Containers are shared by a background task that cannot be rolled back: they go last, once every direct share succeeded.
    const orderedTargets = [...targets.filter((target) => !target.isContainer), ...targets.filter((target) => target.isContainer)];
    // Inside a workflow transition, each container task is tracked as an async slot: the transition, and the decision record,
    // only complete once the task finished. Outside one (no slot accumulator), the task is enqueued untracked.
    const { pendingAsyncSlots, __workflowInstanceId } = executionContext as any;
    const tracksContainerTasks = Array.isArray(pendingAsyncSlots) && !!__workflowInstanceId;
    const directlyShared: typeof targets = [];
    const queuedTasks: { taskId: string; slot: AsyncActionSlot }[] = [];
    try {
      for (const target of orderedTargets) {
        if (target.isContainer && tracksContainerTasks) {
          if (target.newOrganizationIds.length === 0) continue;
          const slotId = generateInternalId();
          // The same task as a manual container share, created as the approver and tied to the workflow instance
          const task = await createSharingTask({ ...context, user }, 'SHARE', target.id, target.newOrganizationIds, {
            workflowInstanceId: __workflowInstanceId,
            workflowActionId: slotId,
          });
          queuedTasks.push({ taskId: task.id, slot: { id: slotId, workId: task.work_id ?? '', type: 'shareRequestedEntities', status: 'pending' } });
          continue;
        }
        await addOrganizationRestriction(context, user, target.id, organizationIds);
        if (!target.isContainer && target.newOrganizationIds.length > 0) {
          directlyShared.push(target);
        }
      }
    } catch (error) {
      // Undo what this action did, so a refused decision leaves the targets as they were:
      // delete the container tasks already queued (a task the task manager already started keeps what it shared),
      if (queuedTasks.length > 0) {
        const { deleteTask } = await import('../../../domain/backgroundTask');
        for (const { taskId } of queuedTasks) {
          try {
            await deleteTask({ ...context, user }, user, taskId);
          } catch (rollbackError) {
            logApp.error('[shareRequestedEntities] Failed to delete a queued share task after a refused share', { cause: rollbackError, taskId });
          }
        }
      }
      // then remove the grants added directly.
      for (const target of directlyShared) {
        try {
          await removeOrganizationRestriction(context, user, target.id, target.newOrganizationIds);
        } catch (rollbackError) {
          logApp.error('[shareRequestedEntities] Failed to undo a grant after a refused share', { cause: rollbackError, targetId: target.id });
        }
      }
      throw error;
    }
    // Registered once every task is queued: a refused share registers no slot
    if (queuedTasks.length > 0) {
      pendingAsyncSlots.push(...queuedTasks.map(({ slot }) => slot));
    }
  },
  /**
   * asyncBulkAction: spawns a BackgroundTask + Work via createListTask.
   * The slot is pushed onto ctx.pendingAsyncSlots (mutable accumulator).
   * createListTask is injected at trigger time via ctx.__createListTask to avoid
   * a direct import cycle between the registry and backgroundTask-common.js.
   */
  asyncBulkAction: async (executionContext, params) => {
    const { entity, user, context, pendingAsyncSlots, __createListTask, __workflowInstanceId, __draftEntityIds } = executionContext as any;
    if (typeof __createListTask !== 'function') {
      logApp.error('[asyncBulkAction] __createListTask not injected into context — action skipped');
      return;
    }

    const { scope, description, failOnAnyError = true } = params ?? {};
    const runtimeParams: Record<string, unknown> = (executionContext as any).runtimeParams ?? {};

    // Inject org IDs from runtimeParams into actions that have empty context.values.
    // This handles transitions where orgs are collected at trigger time (not pre-filled in definition).
    const actions = ((params?.actions ?? []) as any[]).map((a: any) => {
      if (a.type === 'SHARE' && !a.context?.values?.length) {
        const orgIds: string[] = (runtimeParams.shareOrganizationIds as string[]) ?? (runtimeParams.organizationIds as string[]) ?? [];
        if (orgIds.length > 0) return { ...a, context: { ...a.context, values: orgIds } };
      }
      if (a.type === 'UNSHARE' && !a.context?.values?.length) {
        const orgIds: string[] = (runtimeParams.unshareOrganizationIds as string[]) ?? (runtimeParams.organizationIds as string[]) ?? [];
        if (orgIds.length > 0) return { ...a, context: { ...a.context, values: orgIds } };
      }
      return a;
    });

    const isDraft = entity?.entity_type === 'DraftWorkspace';
    const draftEntityIds: string[] = __draftEntityIds ?? [];

    // Resolve entity IDs:
    // - DraftWorkspace with pre-queried contents → use those STIX entity IDs
    // - DraftWorkspace linked to a specific entity (entity_id set) → use that ID
    // - Any other entity → use its own ID
    const fallbackId = (isDraft && entity?.entity_id) ? entity.entity_id : entity?.id;
    const ids: string[] = (isDraft && draftEntityIds.length > 0) ? draftEntityIds : (fallbackId ? [fallbackId] : []);

    // When targeting a DraftWorkspace, run the task in the draft context
    // so internalFindByIds can locate the entities (they live in the draft index).
    const taskContext = isDraft ? { ...context, draft_context: entity.internal_id } : context;

    // Generate the slot ID here so it can be stored on the BackgroundTask as workflow_action_id.
    // work.js checks for this field to call reportWorkflowAsyncActionResult on completion.
    const slotId = generateInternalId();

    const task = await __createListTask(taskContext, user, {
      scope,
      description: description ?? 'Workflow async bulk action',
      actions,
      ids,
      workflow_instance_id: __workflowInstanceId,
      workflow_action_id: slotId,
    });

    const slot: AsyncActionSlot = {
      id: slotId,
      workId: task.work_id ?? '',
      type: 'asyncBulkAction',
      status: 'pending',
    };

    if (Array.isArray(pendingAsyncSlots)) {
      pendingAsyncSlots.push({ ...slot, _failOnAnyError: failOnAnyError });
    }
  },
};

export const ActionDefinitions: Record<string, ActionDefinition> = {
  log: {
    fn: ActionRegistry.log,
    paramsSchema: z.object({ message: z.string().optional() }).optional(),
    allowedModes: ['sync', 'async'],
  },
  validateDraft: {
    fn: ActionRegistry.validateDraft,
    paramsSchema: z.object({}).optional(),
    allowedModes: ['sync', 'async'],
  },
  updateAuthorizedMembers: {
    fn: ActionRegistry.updateAuthorizedMembers,
    paramsSchema: z.object({
      authorized_members: z.array(z.object({
        id: z.string(),
        access_right: z.string(),
        groups_restriction_ids: z.array(z.string()).optional(),
      })).optional(),
    }).optional(),
    allowedModes: ['sync', 'async'],
  },
  shareRequestedEntities: {
    fn: ActionRegistry.shareRequestedEntities,
    paramsSchema: z.object({ organizations: z.array(z.string()).min(1) }),
    allowedModes: ['sync'],
  },
  asyncBulkAction: {
    fn: ActionRegistry.asyncBulkAction,
    paramsSchema: asyncBulkActionParamsSchema,
    allowedModes: ['async'], // Only valid in asyncActions[], never in syncActions[]
  },
};
