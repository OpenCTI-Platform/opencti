import { logApp } from '../../../config/conf';
import { draftWorkspaceEditAuthorizedMembers, validateDraftWorkspace } from '../../draftWorkspace/draftWorkspace-domain';
import type { AsyncActionSlot, Context } from '../types/workflow-types';
import { generateInternalId } from '../../../schema/identifier';
import { z } from 'zod';
import { editAuthorizedMembers } from '../../../utils/authorizedMembers';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../organization/organization-types';
import type { MemberAccessInput } from '../../../generated/graphql';
import { KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS } from '../../../utils/access';
import { storeLoadById } from '../../../database/middleware-loader';
import { RELATION_CREATED_BY, RELATION_OBJECT_ASSIGNEE, RELATION_OBJECT_PARTICIPANT } from '../../../schema/stixRefRelationship';

/**
 * Resolves dynamic authorized member keys (AUTHOR, CREATORS, ASSIGNEES, PARTICIPANTS)
 */
const resolveDynamicAuthorizedMembers = async (
  context: any,
  user: any,
  entity: any,
  rawMembers: Array<{ id: string; access_right: string; groups_restriction_ids?: string[] }>,
): Promise<MemberAccessInput[]> => {
  const resolved: MemberAccessInput[] = [];
  for (const member of rawMembers) {
    const { id, access_right, groups_restriction_ids } = member;
    if (id === 'AUTHOR') {
      // RELATION_CREATED_BY is the denormalized flat field name for the author relation in ES
      const createdById = entity[RELATION_CREATED_BY] as string | undefined;
      if (createdById) {
        const authorEntity = await storeLoadById(context, user, createdById, 'Basic-Object').catch(() => null);
        if (authorEntity?.entity_type === ENTITY_TYPE_IDENTITY_ORGANIZATION) {
          resolved.push({ id: createdById, access_right, groups_restriction_ids });
        }
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
    const resolvedMembers = await resolveDynamicAuthorizedMembers(context, user, entity, rawMembers);

    if (entity?.entity_type === 'DraftWorkspace') {
      await draftWorkspaceEditAuthorizedMembers(context, user, entity.id, resolvedMembers);
    } else {
      await editAuthorizedMembers(context, user, {
        entityId: entity.id ?? entity.internal_id,
        input: resolvedMembers,
        requiredCapabilities: [KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS],
        entityType: entity.entity_type,
      });
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
  asyncBulkAction: {
    fn: ActionRegistry.asyncBulkAction,
    paramsSchema: asyncBulkActionParamsSchema,
    allowedModes: ['async'], // Only valid in asyncActions[], never in syncActions[]
  },
};
