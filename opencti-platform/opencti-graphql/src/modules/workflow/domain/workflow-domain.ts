import { randomUUID } from 'node:crypto';
import { FunctionalError } from '../../../config/errors';
import { createEntity, createRelation, loadEntity, updateAttribute } from '../../../database/middleware';
import { fullEntitiesList, storeLoadById } from '../../../database/middleware-loader';
import { createListTask } from '../../../domain/backgroundTask-common';
import { FilterMode, type EditInput } from '../../../generated/graphql';
import { generateInternalId } from '../../../schema/identifier';
import { RELATION_HAS_WORKFLOW } from '../../../schema/internalRelationship';
import type { BasicStoreEntity } from '../../../types/store';
import type { AuthContext, AuthUser } from '../../../types/user';
import { bypassDraftContext } from '../../../utils/draftContext';
import { findByType as findEntitySettingByType } from '../../entitySetting/entitySetting-domain';
import type { BasicStoreEntityEntitySetting } from '../../entitySetting/entitySetting-types';
import { WorkflowFactory } from '../engine/workflow-factory';
import type { WorkflowSchema } from '../engine/workflow-schema';
import { READ_INDEX_DRAFT_OBJECTS, READ_INDEX_HISTORY } from '../../../database/utils';
import { DRAFT_OPERATION_UPDATE_LINKED } from '../../draftWorkspace/draftOperations';
import {
  ENTITY_TYPE_WORKFLOW_DEFINITION,
  ENTITY_TYPE_WORKFLOW_INSTANCE,
  type AsyncActionSlot,
  type TriggerResult,
  type WorkflowValidationError,
  type WorkflowActionConfig,
  type WorkflowPendingTransition,
} from '../types/workflow-types';
import { validateWorkflowDefinitionData } from '../workflow-validation';

// Domain-specific types
interface WorkflowVersion {
  id: string;
  timestamp: string;
  createdBy: string;
  content: string;
  validation_errors: WorkflowValidationError[];
}

interface WorkflowDefinitionEntity extends BasicStoreEntity {
  name: string;
  published_version?: WorkflowVersion;
  draft_version?: WorkflowVersion;
  all_versions: WorkflowVersion[];
}

interface WorkflowDefinitionResponse extends WorkflowSchema {
  published: boolean;
}

interface EntitySettingWithWorkflowResponse {
  errors: WorkflowValidationError[];
  published: boolean;
  id: string;
  workflow_id?: string | null;
  target_type: string;
}

/**
 * Validate workflow version consistency.
 * Ensures that draft_version and published_version are present in all_versions.
 */
const validateVersionConsistency = (workflowEntity: WorkflowDefinitionEntity): void => {
  const { draft_version, published_version, all_versions } = workflowEntity;

  if (!all_versions || !Array.isArray(all_versions)) {
    throw FunctionalError('all_versions must be an array');
  }

  // Check draft_version is in all_versions
  if (draft_version) {
    const draftInHistory = all_versions.some((v) => v.id === draft_version.id);
    if (!draftInHistory) {
      throw FunctionalError('Consistency error: draft_version not found in all_versions', {
        draftVersionId: draft_version.id,
      });
    }
  }

  // Check published_version is in all_versions
  if (published_version) {
    const publishedInHistory = all_versions.some((v) => v.id === published_version.id);
    if (!publishedInHistory) {
      throw FunctionalError('Consistency error: published_version not found in all_versions', {
        publishedVersionId: published_version.id,
      });
    }
  }
};

interface WorkflowInstanceStoreEntity extends BasicStoreEntity {
  currentState: string;
  history: string;
  pendingStatus?: string | null;
  pendingError?: string | null;
  pendingTransition?: string | null;
  entity_id: string;
}

const getWorkflowConfig = async (
  context: AuthContext,
  user: AuthUser,
  targetType: string,
): Promise<BasicStoreEntityEntitySetting | undefined> => {
  const executionContext = bypassDraftContext(context);
  return findEntitySettingByType(executionContext, executionContext.user!, targetType);
};

/**
 * Get workflow definition data based on allowDraft parameter.
 */
const getDefinitionData = async (
  context: AuthContext,
  user: AuthUser,
  entitySetting: BasicStoreEntityEntitySetting | undefined,
  allowDraft: boolean = false,
): Promise<WorkflowDefinitionResponse | null> => {
  if (!entitySetting) return null;

  if (entitySetting.workflow_id) {
    const executionContext = bypassDraftContext(context);
    const workflowDefinitionEntity = await storeLoadById(
      executionContext,
      executionContext.user!,
      entitySetting.workflow_id,
      ENTITY_TYPE_WORKFLOW_DEFINITION,
    ) as WorkflowDefinitionEntity | undefined;
    if (workflowDefinitionEntity) {
      // Choose version based on allowDraft parameter
      let version;
      if (allowDraft) {
        // For UI editing: draft_version if exists, otherwise published_version
        version = workflowDefinitionEntity.draft_version || workflowDefinitionEntity.published_version;
      } else {
        // For runtime execution: ONLY published_version (no fallback)
        version = workflowDefinitionEntity.published_version;
      }

      if (!version?.content) return null;

      const workflowContent = typeof version.content === 'string'
        ? JSON.parse(version.content)
        : version.content;

      // Determine if draft and published are the same
      const draftVersion = workflowDefinitionEntity.draft_version;
      const publishedVersion = workflowDefinitionEntity.published_version;
      const published = !draftVersion || (publishedVersion?.id === draftVersion?.id);
      const errors = version.validation_errors || [];

      return {
        ...workflowContent,
        id: workflowDefinitionEntity.id,
        name: workflowDefinitionEntity.name,
        published,
        errors,
      };
    }
  }

  return null;
};

const findWorkflowInstanceEntity = async (
  context: AuthContext,
  user: AuthUser,
  entityId: string,
): Promise<WorkflowInstanceStoreEntity | null> => {
  // Find existing instance via entity_id attribute directly (more robust than relationship)
  const executionContext = bypassDraftContext(context);
  return await loadEntity(executionContext, executionContext.user!, [ENTITY_TYPE_WORKFLOW_INSTANCE], {
    filters: {
      mode: FilterMode.And,
      filters: [{ key: ['entity_id'], values: [entityId] }],
      filterGroups: [],
    },
  }) as WorkflowInstanceStoreEntity;
};

const initializeWorkflowInstance = async (
  context: AuthContext,
  user: AuthUser,
  entity: BasicStoreEntity & { id?: string; internal_id?: string },
  entitySetting: BasicStoreEntityEntitySetting,
  definitionData: WorkflowDefinitionResponse,
): Promise<WorkflowInstanceStoreEntity> => {
  const initialState = definitionData.initialState;
  const entityId = entity.id || entity.internal_id;
  const instanceInput = {
    entity_id: entityId,
    workflow_id: entitySetting.workflow_id || 'manual',
    currentState: initialState,
    history: JSON.stringify([{
      state: initialState,
      user_id: user.id,
      timestamp: new Date().toISOString(),
      event: 'initialization',
    }]),
  };
  const executionContext = bypassDraftContext(context);
  const executionUser = executionContext.user!;
  const instance = await createEntity(executionContext, executionUser, instanceInput, ENTITY_TYPE_WORKFLOW_INSTANCE) as WorkflowInstanceStoreEntity;

  await createRelation(executionContext, executionUser, {
    fromId: entityId,
    toId: instance.id || instance.internal_id,
    relationship_type: RELATION_HAS_WORKFLOW,
  });

  return instance;
};

/**
 * Get workflow definition for an entity type.
 */
export const getWorkflowDefinition = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
  allowDraft: boolean = false,
): Promise<WorkflowDefinitionResponse | null> => {
  const entitySetting = await getWorkflowConfig(context, user, entityType);
  return getDefinitionData(context, user, entitySetting, allowDraft);
};

/**
 * Create or update workflow definition for an entity type.
 */
export const setWorkflowDefinition = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
  definition: string,
): Promise<EntitySettingWithWorkflowResponse> => {
  const entitySetting = await getWorkflowConfig(context, user, entityType);
  if (!entitySetting) {
    throw FunctionalError('Entity setting not found for type', { entityType });
  }

  // Validate definition is valid JSON and respect schema
  let definitionObj;
  try {
    definitionObj = JSON.parse(definition);
  } catch (_error) {
    throw FunctionalError('Invalid workflow definition JSON');
  }

  const executionContext = bypassDraftContext(context);
  const executionUser = executionContext.user!;

  const errors = await validateWorkflowDefinitionData(executionContext, executionUser, definition, entityType, entitySetting.workflow_id ?? undefined);

  const workflowName = definitionObj.name || `Workflow for ${entityType}`;

  // Create version data structure
  const versionData = {
    id: randomUUID(),
    timestamp: new Date().toISOString(),
    createdBy: executionUser.id,
    content: definition,
    validation_errors: errors,
  };

  // 1. Check if we have an existing workflow linked
  if (entitySetting.workflow_id) {
    const existingWorkflow = await storeLoadById(
      executionContext,
      executionUser,
      entitySetting.workflow_id,
      ENTITY_TYPE_WORKFLOW_DEFINITION,
    ) as WorkflowDefinitionEntity | undefined;
    if (existingWorkflow) {
      // Add to version history (prepend new version to maintain chronological order).
      // Cap at 100 entries to prevent unbounded growth (e.g. from a save loop triggered by UI hooks).
      const MAX_VERSIONS = 100;
      const allVersions = existingWorkflow.all_versions || [];
      const updatedVersions = [versionData, ...allVersions].slice(0, MAX_VERSIONS);

      // draft_version is always in all_versions
      await updateAttribute(executionContext, executionUser, existingWorkflow.id, ENTITY_TYPE_WORKFLOW_DEFINITION, [
        { key: 'draft_version', value: [versionData] },
        { key: 'all_versions', value: updatedVersions },
        { key: 'name', value: [workflowName] },
      ]);

      const updatedWorkflow = await storeLoadById(
        executionContext,
        executionUser,
        existingWorkflow.id,
        ENTITY_TYPE_WORKFLOW_DEFINITION,
      ) as WorkflowDefinitionEntity;
      validateVersionConsistency(updatedWorkflow);

      // Check if draft matches published
      const published = updatedWorkflow.published_version?.id === versionData.id;

      return {
        ...entitySetting,
        errors,
        published,
      } as EntitySettingWithWorkflowResponse;
    }
  }

  // 2. Create the WorkflowDefinition entity
  // Initial draft_version is in all_versions
  const workflowDefinitionInput = {
    name: workflowName,
    draft_version: versionData,
    all_versions: [versionData],
  };
  const workflowDefinition = await createEntity(
    executionContext,
    executionUser,
    workflowDefinitionInput,
    ENTITY_TYPE_WORKFLOW_DEFINITION,
  ) as WorkflowDefinitionEntity;

  // Validate consistency after creation
  validateVersionConsistency(workflowDefinition);

  // 3. Link it to the EntitySetting
  const { element } = await updateAttribute(executionContext, executionUser, entitySetting.id, 'EntitySetting', [
    { key: 'workflow_id', value: [workflowDefinition.id] },
  ]);

  // New workflows have no published version yet
  const published = false;

  const elementWithSetting = element as unknown as BasicStoreEntityEntitySetting;
  return {
    id: elementWithSetting.id,
    workflow_id: elementWithSetting.workflow_id,
    target_type: elementWithSetting.target_type,
    errors,
    published,
  } as EntitySettingWithWorkflowResponse;
};

/**
 * Delete workflow definition for an entity type.
 */
export const deleteWorkflowDefinition = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
): Promise<BasicStoreEntityEntitySetting | undefined> => {
  const entitySetting = await getWorkflowConfig(context, user, entityType);
  if (entitySetting?.workflow_id) {
    const executionContext = bypassDraftContext(context);
    const { element } = await updateAttribute(executionContext, executionContext.user!, entitySetting.id, 'EntitySetting', [
      { key: 'workflow_id', value: [null] },
    ]);
    return element as unknown as BasicStoreEntityEntitySetting;
  }
  return entitySetting;
};

/**
 * Publish the draft workflow definition (copy draft_version to published_version).
 */
export const publishWorkflowDefinition = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
): Promise<EntitySettingWithWorkflowResponse> => {
  const entitySetting = await getWorkflowConfig(context, user, entityType);
  if (!entitySetting) {
    throw FunctionalError('Entity setting not found for type', { entityType });
  }

  if (!entitySetting.workflow_id) {
    throw FunctionalError('No workflow definition to publish', { entityType });
  }

  const executionContext = bypassDraftContext(context);
  const executionUser = executionContext.user!;

  const workflowDefinitionEntity = await storeLoadById(
    executionContext,
    executionUser,
    entitySetting.workflow_id,
    ENTITY_TYPE_WORKFLOW_DEFINITION,
  ) as WorkflowDefinitionEntity | undefined;
  if (!workflowDefinitionEntity) {
    throw FunctionalError('Workflow definition not found', { workflowId: entitySetting.workflow_id });
  }

  const draftVersion = workflowDefinitionEntity.draft_version;
  if (!draftVersion) {
    throw FunctionalError('No draft version to publish', { entityType });
  }

  // Check for validation errors
  if (draftVersion.validation_errors && draftVersion.validation_errors.length > 0) {
    throw FunctionalError('Cannot publish workflow with validation errors', {
      entityType,
      errorCount: draftVersion.validation_errors.length,
    });
  }

  // Validate consistency BEFORE publishing
  const allVersions = workflowDefinitionEntity.all_versions || [];
  const draftInHistory = allVersions.some((version: WorkflowVersion) => version.id === draftVersion.id);
  if (!draftInHistory) {
    throw FunctionalError('Consistency error: Cannot publish draft_version that is not in all_versions', {
      draftVersionId: draftVersion.id,
    });
  }

  // CONSISTENCY GUARANTEE: published_version will be in all_versions (already there via draft)
  // Copy draft_version to published_version and clear the draft (no more unpublished changes).
  const updates: EditInput[] = [
    { key: 'published_version', value: [draftVersion] },
    { key: 'draft_version', value: [] },
  ];

  await updateAttribute(executionContext, executionUser, workflowDefinitionEntity.id, ENTITY_TYPE_WORKFLOW_DEFINITION, updates);

  const updatedWorkflow = await storeLoadById(
    executionContext,
    executionUser,
    workflowDefinitionEntity.id,
    ENTITY_TYPE_WORKFLOW_DEFINITION,
  ) as WorkflowDefinitionEntity;
  // Validate consistency after update
  validateVersionConsistency(updatedWorkflow);

  const entitySettingWithWorkflow = entitySetting as BasicStoreEntityEntitySetting;
  return {
    id: entitySettingWithWorkflow.id,
    workflow_id: entitySettingWithWorkflow.workflow_id,
    target_type: entitySettingWithWorkflow.target_type,
    errors: [],
    published: true,
  } as EntitySettingWithWorkflowResponse;
};

/**
 * Get workflow instance for an entity, with live pending transition data.
 */
export const getWorkflowInstance = async (
  context: AuthContext,
  user: AuthUser,
  entityId: string,
): Promise<any> => {
  const entity = await storeLoadById(context, user, entityId, 'Basic-Object');
  if (!entity) {
    return null;
  }

  const entitySetting = await getWorkflowConfig(context, user, entity.entity_type);
  const definitionData = await getDefinitionData(context, user, entitySetting);
  if (!definitionData) {
    return null;
  }

  const effectiveEntityId = entity.internal_id || entity.id;
  const instanceEntity = await findWorkflowInstanceEntity(context, user, effectiveEntityId);
  const currentState = instanceEntity?.currentState ?? definitionData.initialState;

  const allowedTransitions = await getAllowedTransitions(context, user, entityId);
  const id = instanceEntity?.internal_id ?? instanceEntity?.id ?? `initial-${effectiveEntityId}`;

  // Parse pending transition and enrich with live Work data
  let pendingTransitionData: WorkflowPendingTransition | null = null;
  if (instanceEntity?.pendingTransition) {
    try {
      const raw: WorkflowPendingTransition = typeof instanceEntity.pendingTransition === 'string'
        ? JSON.parse(instanceEntity.pendingTransition)
        : instanceEntity.pendingTransition;

      // Enrich each slot with live BackgroundTask + Work entity data
      const enrichedSlots = await Promise.all(
        raw.asyncActions.map(async (slot) => {
          if (!slot.workId) return slot;
          const workEntity = await storeLoadById<any>(context, user, slot.workId, 'Work', { indices: [READ_INDEX_HISTORY] }).catch(() => null);
          if (!workEntity) return slot;
          // The BackgroundTask has task_expected_number (set at creation = ids.length)
          // and task_processed_number (updated per iteration by the task manager).
          // These are more reliable than Work's import_expected_number (which starts at 0
          // in Redis and is only updated in ES after the task manager runs).
          let processedCount = 0;
          let expectedCount = 0;
          const backgroundTaskId = workEntity.background_task_id;
          if (backgroundTaskId) {
            const bgTask = await storeLoadById<any>(context, user, backgroundTaskId, 'BackgroundTask').catch(() => null);
            if (bgTask) {
              expectedCount = bgTask.task_expected_number ?? 0;
              processedCount = bgTask.task_processed_number ?? 0;
            }
          }
          return {
            ...slot,
            processedCount,
            expectedCount,
            startedAt: workEntity.received_time ?? null,
            lastActivityAt: workEntity.updated_at ?? null,
            errors: (workEntity.errors ?? []).slice(0, 100),
            workStatus: workEntity.status ?? null,
          };
        }),
      );
      pendingTransitionData = { ...raw, asyncActions: enrichedSlots };
    } catch {
      // Malformed JSON — surface as null, admin can use clearWorkflowPendingState
    }
  }

  return {
    id,
    internal_id: id,
    __typename: 'WorkflowInstance',
    currentState: currentState || '',
    allowedTransitions,
    history: JSON.parse(instanceEntity?.history || '[]'),
    pendingStatus: instanceEntity?.pendingStatus ?? null,
    pendingError: instanceEntity?.pendingError ?? null,
    pendingTransition: pendingTransitionData,
  };
};

/**
 * Get allowed transitions for an entity.
 */
export const getAllowedTransitions = async (
  context: AuthContext,
  user: AuthUser,
  entityId: string,
): Promise<Array<{ event: string; toState: string; comment?: string; actions: string[] }>> => {
  const entity = await storeLoadById(context, user, entityId, 'Basic-Object');
  if (!entity) {
    return [];
  }

  const entitySetting = await getWorkflowConfig(context, user, entity.entity_type);
  const definitionData = await getDefinitionData(context, user, entitySetting);

  if (!definitionData) {
    return [];
  }

  const effectiveEntityId = entity.internal_id || entity.id;
  const instanceEntity = await findWorkflowInstanceEntity(context, user, effectiveEntityId);
  const currentStateId = instanceEntity?.currentState ?? definitionData.initialState;

  const definition = WorkflowFactory.createDefinition(definitionData);
  const effectiveStateId = currentStateId || definition.getInitialState();
  if (!effectiveStateId || !definition.hasState(effectiveStateId)) {
    return [];
  }

  const transitions = definition.getTransitions(effectiveStateId);

  const resolvedTransitions = transitions.map((transition) => {
    return {
      event: transition.event,
      toState: transition.to,
      comment: transition.comment,
      actions: transition.actionTypes || [],
      requiresOrganizationInput: transition.requiresOrganizationInput ?? false,
    };
  });

  return resolvedTransitions;
};

/**
 * Trigger a workflow event on an entity.
 * This is the main entry point for the backend logic.
 *
 * @param context The auth context
 * @param user The auth user
 * @param entityId The ID of the entity to trigger the event on
 * @param eventName The name of the event to trigger
 * @param comment Optional comment entered by the user when performing the transition
 * @param runtimeParams Optional runtime parameters (e.g. organizationIds for share actions). Persisted for retry.
 * @returns {Promise<TriggerResult>} The result of the trigger
 */
export const triggerWorkflowEvent = async (
  context: AuthContext,
  user: AuthUser,
  entityId: string,
  eventName: string,
  comment?: string,
  runtimeParams: Record<string, unknown> = {},
): Promise<TriggerResult> => {
  // 1. Fetch the entity
  const entity = await storeLoadById(context, user, entityId, 'Basic-Object');
  if (!entity) {
    throw FunctionalError('Entity not found', { entityId });
  }

  // 2. Fetch its EntitySetting to get the workflow configuration
  const entitySetting = await getWorkflowConfig(context, user, entity.entity_type);
  const definitionData = await getDefinitionData(context, user, entitySetting);

  if (!definitionData) {
    return {
      success: false,
      reason: `Workflows are not configured for entity type: ${entity.entity_type}`,
    };
  }

  try {
    const executionContext = bypassDraftContext(context);
    const executionUser = executionContext.user!;

    if (!entitySetting) {
      throw FunctionalError('Entity setting not found', { entityType: entity.entity_type });
    }

    const effectiveEntityId = entity.internal_id || entity.id;
    let instanceEntity = await findWorkflowInstanceEntity(executionContext, executionUser, effectiveEntityId);
    if (!instanceEntity) {
      instanceEntity = await initializeWorkflowInstance(
        executionContext,
        executionUser,
        entity as BasicStoreEntity & { id?: string; internal_id?: string },
        entitySetting,
        definitionData,
      );
    }

    // 3. Lock check: reject new events while a transition is already pending
    if (instanceEntity.pendingStatus === 'pending') {
      return {
        success: false,
        reason: 'A workflow transition is already pending for this entity. Wait for it to complete, retry the failed action, or ask an admin to clear the pending state.',
      };
    }

    const currentStateId = instanceEntity.currentState;
    const definition = WorkflowFactory.createDefinition(definitionData);

    // 4. Inject createListTask and instance metadata into context for asyncBulkAction.
    // When the workflow entity is a DraftWorkspace, pre-query only the STIX entities that
    // belong to this specific draft (using the dedicated draft index + draft_ids filter).
    const draftEntityIds: string[] = [];
    if ((entity as any).entity_type === 'DraftWorkspace') {
      const draftId = (entity as any).internal_id;
      const draftCtx = { ...executionContext, draft_context: draftId };
      const draftFilter = {
        mode: FilterMode.And,
        filters: [{ key: ['draft_ids'], values: [draftId] }],
        filterGroups: [],
      };
      const draftItems = await fullEntitiesList<any>(draftCtx, executionUser, ['Stix-Core-Object'], {
        indices: [READ_INDEX_DRAFT_OBJECTS],
        filters: draftFilter,
      });
      // Exclude update_linked entities — these are entities indirectly pulled into the draft
      // (e.g. organizations referenced by new sharing relations) and should not be targeted
      // by subsequent async actions like org sharing/unsharing.
      draftEntityIds.push(...draftItems
        .filter((item: any) => item.draft_change?.draft_operation !== DRAFT_OPERATION_UPDATE_LINKED)
        .map((item: any) => item.internal_id)
        .filter(Boolean));
    }

    const workflowContext = {
      entity,
      user: executionUser,
      context: executionContext,
      runtimeParams,
      __createListTask: createListTask,
      __workflowInstanceId: instanceEntity.internal_id || instanceEntity.id,
      __draftEntityIds: draftEntityIds,
    };

    // 5. Create instance and trigger the event
    const instance = WorkflowFactory.getInstance(definitionData, definition, currentStateId || '', workflowContext);
    const result = await instance.trigger(eventName);

    if (!result.success) {
      return { ...result, entity };
    }

    const instanceId = instanceEntity.internal_id || instanceEntity.id;

    // 6a. Async transition: persist pendingTransition, do NOT advance state
    if (result.executionStatus === 'pending' && result.asyncActionSlots && result.asyncActionSlots.length > 0) {
      // The action already generated stable slot IDs (identical to workflow_action_id on the BackgroundTask)
      const rawSlots: AsyncActionSlot[] = result.asyncActionSlots.map((rawSlot: any) => ({
        id: rawSlot.id,
        workId: rawSlot.workId,
        type: rawSlot.type,
        status: 'pending' as const,
      }));

      // Get the serialized transition to persist its syncActions for phase-2 execution.
      // Use length check instead of ?? because the frontend always serializes syncActions as [] (empty array),
      // which is truthy and would prevent the fallback to the legacy actions[] field.
      const targetTransitionForSync = definitionData.transitions?.find((t: any) => {
        const fromStates = Array.isArray(t.from) ? t.from : [t.from];
        return fromStates.includes(currentStateId) && t.event === eventName;
      });
      const serializedTransitions: WorkflowActionConfig[] = (targetTransitionForSync?.syncActions?.length
        ? targetTransitionForSync.syncActions
        : null) ?? targetTransitionForSync?.actions ?? [];

      const pendingTransition: WorkflowPendingTransition = {
        event: eventName,
        toState: targetTransitionForSync?.to ?? instance.getCurrentState(),
        triggeredBy: user.id,
        triggeredAt: new Date().toISOString(),
        runtimeParams,
        asyncActions: rawSlots,
        syncActions: serializedTransitions,
      };

      await updateAttribute(executionContext, executionUser, instanceId, ENTITY_TYPE_WORKFLOW_INSTANCE, [
        { key: 'pendingStatus', value: ['pending'] },
        { key: 'pendingError', value: [null] },
        { key: 'pendingTransition', value: [JSON.stringify(pendingTransition)] },
      ]);

      const workflowInstance = await getWorkflowInstance(context, user, entityId);
      return {
        success: true,
        executionStatus: 'pending',
        instance: workflowInstance,
        entity,
      };
    }

    // 6b. Sync-only transition: state already advanced by engine — persist the new state
    const newState = instance.getCurrentState();
    let history: any[];
    try {
      history = JSON.parse(instanceEntity.history || '[]');
    } catch {
      history = [];
    }

    history.push({
      state: newState,
      user_id: user.id,
      timestamp: new Date().toISOString(),
      event: eventName,
      ...(comment ? { comment } : {}),
    });

    await updateAttribute(executionContext, executionUser, instanceId, ENTITY_TYPE_WORKFLOW_INSTANCE, [
      { key: 'currentState', value: [newState] },
      { key: 'history', value: [JSON.stringify(history)] },
    ]);

    const workflowInstance = await getWorkflowInstance(context, user, entityId);
    return { success: true, newState, executionStatus: 'completed', instance: workflowInstance, entity };
  } catch (error) {
    const reason = error instanceof Error ? error.message : 'Unknown error';
    return {
      success: false,
      reason: `Workflow execution failed: ${reason}`,
    };
  }
};

export const isStatusTemplateUsedInWorkflows = async (
  context: AuthContext,
  user: AuthUser,
  statusTemplateId: string,
): Promise<boolean> => {
  const executionContext = bypassDraftContext(context);
  const workflows = await fullEntitiesList<WorkflowDefinitionEntity>(
    executionContext,
    executionContext.user!,
    [ENTITY_TYPE_WORKFLOW_DEFINITION],
  );
  for (const workflow of workflows) {
    // Check both published and draft versions
    const versions = [workflow.published_version, workflow.draft_version].filter((v): v is WorkflowVersion => v !== undefined && v !== null);
    for (const version of versions) {
      const content = version.content;
      if (typeof content === 'string' && content.includes(statusTemplateId)) {
        return true;
      } else if (content && JSON.stringify(content).includes(statusTemplateId)) {
        return true;
      }
    }
  }
  return false;
};

/**
 * Re-enqueue only the failed async action slots of a pending transition.
 * Available when pendingStatus = 'error'. Reuses stored runtimeParams — no user re-prompt.
 */
export const retryPendingWorkflowTransitionActions = async (
  context: AuthContext,
  user: AuthUser,
  entityId: string,
): Promise<TriggerResult> => {
  const entity = await storeLoadById(context, user, entityId, 'Basic-Object');
  if (!entity) throw FunctionalError('Entity not found', { entityId });

  const executionContext = bypassDraftContext(context);
  const executionUser = executionContext.user!;
  const effectiveEntityId = entity.internal_id || entity.id;
  const instanceEntity = await findWorkflowInstanceEntity(executionContext, executionUser, effectiveEntityId);

  if (!instanceEntity) throw FunctionalError('No workflow instance found for entity', { entityId });
  if (instanceEntity.pendingStatus !== 'error') {
    return { success: false, reason: 'Retry is only available when pendingStatus is "error"' };
  }

  let pendingTransition: WorkflowPendingTransition;
  try {
    pendingTransition = typeof instanceEntity.pendingTransition === 'string'
      ? JSON.parse(instanceEntity.pendingTransition)
      : instanceEntity.pendingTransition;
  } catch {
    throw FunctionalError('pendingTransition is malformed; use clearWorkflowPendingState to reset');
  }

  const updatedSlots: AsyncActionSlot[] = [];

  for (const slot of pendingTransition.asyncActions) {
    if (slot.status !== 'failed') {
      updatedSlots.push(slot); // success/pending slots pass through unchanged
      continue;
    }

    // Re-enqueue the failed task with new UUIDs (old task remains but is orphaned)
    const newSlotId = generateInternalId();
    const task = await createListTask(executionContext, executionUser, {
      scope: 'KNOWLEDGE',
      description: `Workflow retry: ${pendingTransition.event}`,
      actions: [],
      ids: [effectiveEntityId],
      workflow_instance_id: instanceEntity.internal_id || instanceEntity.id,
      workflow_action_id: newSlotId,
    });

    updatedSlots.push({
      id: newSlotId,
      workId: task.work_id ?? '',
      type: slot.type,
      status: 'pending',
    });
  }

  const updatedPendingTransition: WorkflowPendingTransition = {
    ...pendingTransition,
    asyncActions: updatedSlots,
  };

  const instanceId = instanceEntity.internal_id || instanceEntity.id;
  await updateAttribute(executionContext, executionUser, instanceId, ENTITY_TYPE_WORKFLOW_INSTANCE, [
    { key: 'pendingStatus', value: ['pending'] },
    { key: 'pendingError', value: [null] },
    { key: 'pendingTransition', value: [JSON.stringify(updatedPendingTransition)] },
  ]);

  const workflowInstance = await getWorkflowInstance(context, user, entityId);
  return { success: true, executionStatus: 'pending', instance: workflowInstance, entity };
};

/**
 * Admin escape hatch: force-clear the pending state of a workflow instance.
 * Leaves currentState unchanged. Logs the intervention in history for audit.
 * Any still-running background tasks become orphaned (admin's conscious decision).
 */
export const clearWorkflowPendingState = async (
  context: AuthContext,
  user: AuthUser,
  entityId: string,
): Promise<any> => {
  const entity = await storeLoadById(context, user, entityId, 'Basic-Object');
  if (!entity) throw FunctionalError('Entity not found', { entityId });

  const executionContext = bypassDraftContext(context);
  const executionUser = executionContext.user!;
  const effectiveEntityId = entity.internal_id || entity.id;
  const instanceEntity = await findWorkflowInstanceEntity(executionContext, executionUser, effectiveEntityId);
  if (!instanceEntity) throw FunctionalError('No workflow instance found for entity', { entityId });

  let historyArr: any[];
  try {
    historyArr = JSON.parse(instanceEntity.history || '[]');
  } catch {
    historyArr = [];
  }
  historyArr.push({
    state: instanceEntity.currentState,
    user_id: user.id,
    timestamp: new Date().toISOString(),
    event: 'admin_clear_pending_state',
    note: 'Admin force-cleared pending workflow transition state',
  });

  const instanceId = instanceEntity.internal_id || instanceEntity.id;
  await updateAttribute(executionContext, executionUser, instanceId, ENTITY_TYPE_WORKFLOW_INSTANCE, [
    { key: 'pendingStatus', value: [null] },
    { key: 'pendingError', value: [null] },
    { key: 'pendingTransition', value: [null] },
    { key: 'history', value: [JSON.stringify(historyArr)] },
  ]);

  return getWorkflowInstance(context, user, entityId);
};
