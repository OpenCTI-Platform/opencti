import { FunctionalError } from '../../../config/errors';
import { createEntity, createRelation, loadEntity, updateAttribute } from '../../../database/middleware';
import { fullEntitiesList, storeLoadById } from '../../../database/middleware-loader';
import { FilterMode } from '../../../generated/graphql';
import { RELATION_HAS_WORKFLOW } from '../../../schema/internalRelationship';
import type { BasicStoreEntity } from '../../../types/store';
import type { AuthContext, AuthUser } from '../../../types/user';
import { bypassDraftContext } from '../../../utils/draftContext';
import { generateInternalId } from '../../../schema/identifier';
import { findByType as findEntitySettingByType } from '../../entitySetting/entitySetting-domain';
import { createListTask } from '../../../domain/backgroundTask-common';
import { WorkflowFactory } from '../engine/workflow-factory';
import {
  ENTITY_TYPE_WORKFLOW_DEFINITION,
  ENTITY_TYPE_WORKFLOW_INSTANCE,
  type AsyncActionSlot,
  type TriggerResult,
  type WorkflowActionConfig,
  type WorkflowPendingTransition,
} from '../types/workflow-types';
import { validateWorkflowDefinitionData } from '../workflow-validation';

interface WorkflowInstanceStoreEntity extends BasicStoreEntity {
  currentState: string;
  history: string;
  pendingStatus?: string | null;
  pendingError?: string | null;
  pendingTransition?: string | null;
  entity_id: string;
}

const getWorkflowConfig = async (context: AuthContext, user: AuthUser, targetType: string) => {
  const executionContext = bypassDraftContext(context);
  return findEntitySettingByType(executionContext, executionContext.user!, targetType);
};

const getDefinitionData = async (context: AuthContext, user: AuthUser, entitySetting: any) => {
  if (!entitySetting) return null;

  if (entitySetting.workflow_id) {
    const executionContext = bypassDraftContext(context);
    const workflowDefinitionEntity = await storeLoadById(executionContext, executionContext.user!, entitySetting.workflow_id, ENTITY_TYPE_WORKFLOW_DEFINITION) as any;
    if (workflowDefinitionEntity) {
      const workflowContent = typeof workflowDefinitionEntity.workflow_content === 'string'
        ? JSON.parse(workflowDefinitionEntity.workflow_content)
        : workflowDefinitionEntity.workflow_content;
      return { ...workflowContent, id: workflowDefinitionEntity.id, name: workflowDefinitionEntity.name };
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
  entity: any,
  entitySetting: any,
  definitionData: any,
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
): Promise<any> => {
  const entitySetting = await getWorkflowConfig(context, user, entityType);
  return getDefinitionData(context, user, entitySetting);
};

/**
 * Create or update workflow definition for an entity type.
 */
export const setWorkflowDefinition = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
  definition: string,
): Promise<any> => {
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

  await validateWorkflowDefinitionData(executionContext, executionUser, definition, entityType, entitySetting.workflow_id ?? undefined);

  const workflowName = definitionObj.name || `Workflow for ${entityType}`;

  // 1. Check if we have an existing workflow linked
  if (entitySetting.workflow_id) {
    const existingWorkflow = await storeLoadById(executionContext, executionUser, entitySetting.workflow_id, ENTITY_TYPE_WORKFLOW_DEFINITION);
    if (existingWorkflow) {
      await updateAttribute(executionContext, executionUser, existingWorkflow.id, ENTITY_TYPE_WORKFLOW_DEFINITION, [
        { key: 'workflow_content', value: [definition] },
        { key: 'name', value: [workflowName] },
      ]);
      return entitySetting;
    }
  }

  // 2. Create the WorkflowDefinition entity
  const workflowDefinitionInput = {
    name: workflowName,
    workflow_content: definition,
  };
  const workflowDefinition = await createEntity(executionContext, executionUser, workflowDefinitionInput, ENTITY_TYPE_WORKFLOW_DEFINITION);

  // 3. Link it to the EntitySetting
  const { element } = await updateAttribute(executionContext, executionUser, entitySetting.id, 'EntitySetting', [
    { key: 'workflow_id', value: [workflowDefinition.id] },
  ]);
  return element;
};

/**
 * Delete workflow definition for an entity type.
 */
export const deleteWorkflowDefinition = async (
  context: AuthContext,
  user: AuthUser,
  entityType: string,
): Promise<any> => {
  const entitySetting = await getWorkflowConfig(context, user, entityType);
  if (entitySetting?.workflow_id) {
    const executionContext = bypassDraftContext(context);
    const { element } = await updateAttribute(executionContext, executionContext.user!, entitySetting.id, 'EntitySetting', [
      { key: 'workflow_id', value: [null] },
    ]);
    return element;
  }
  return entitySetting;
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

      // Enrich each slot with live Work entity data (no work.js import — generic loader)
      const enrichedSlots = await Promise.all(
        raw.asyncActions.map(async (slot) => {
          if (!slot.workId) return slot;
          const workEntity = await storeLoadById<any>(context, user, slot.workId, 'Work').catch(() => null);
          if (!workEntity) return slot;
          return {
            ...slot,
            processedCount: workEntity.completed_number ?? 0,
            expectedCount: workEntity.import_expected_number ?? 0,
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
): Promise<any[]> => {
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
      actions: transition.actionTypes || [],
      requiresOrganizationInput: transition.requiresOrganizationInput ?? false,
    };
  });

  return resolvedTransitions;
};

/**
 * Get allowed next statuses for an entity.
 */
export const getAllowedNextStatuses = async (
  context: AuthContext,
  user: AuthUser,
  entityId: string,
): Promise<any[]> => {
  const transitions = await getAllowedTransitions(context, user, entityId);
  return transitions.map((transition) => transition.toStatus).filter((status) => status !== null && status !== undefined);
};

/**
 * Trigger a workflow event on an entity.
 * This is the main entry point for the backend logic.
 *
 * @param context The auth context
 * @param user The auth user
 * @param entityId The ID of the entity to trigger the event on
 * @param eventName The name of the event to trigger
 * @param runtimeParams Optional runtime parameters (e.g. organizationIds for share actions). Persisted for retry.
 * @returns {Promise<TriggerResult>} The result of the trigger
 */
export const triggerWorkflowEvent = async (
  context: AuthContext,
  user: AuthUser,
  entityId: string,
  eventName: string,
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

    const effectiveEntityId = entity.internal_id || entity.id;
    let instanceEntity = await findWorkflowInstanceEntity(executionContext, executionUser, effectiveEntityId);
    if (!instanceEntity) {
      instanceEntity = await initializeWorkflowInstance(executionContext, executionUser, entity, entitySetting, definitionData);
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

    // 4. Inject createListTask and instance metadata into context for asyncBulkAction
    const workflowContext = {
      entity,
      user: executionUser,
      context: executionContext,
      runtimeParams,
      __createListTask: createListTask,
      __workflowInstanceId: instanceEntity.internal_id || instanceEntity.id,
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
      // Build canonical slots with stable UUIDs (the action pushed task.id as a temp id)
      const rawSlots: AsyncActionSlot[] = result.asyncActionSlots.map((rawSlot: any) => {
        const slotId = generateInternalId();
        return {
          id: slotId,
          workId: rawSlot.workId,
          type: rawSlot.type,
          status: 'pending' as const,
        };
      });

      // Get the serialized transition to persist its syncActions for phase-2 execution
      const serializedTransitions: WorkflowActionConfig[] = definitionData.transitions
        ?.find((t: any) => {
          const fromStates = Array.isArray(t.from) ? t.from : [t.from];
          return fromStates.includes(currentStateId) && t.event === eventName;
        })?.syncActions ?? definitionData.transitions
        ?.find((t: any) => {
          const fromStates = Array.isArray(t.from) ? t.from : [t.from];
          return fromStates.includes(currentStateId) && t.event === eventName;
        })?.actions ?? [];

      const targetTransition = definitionData.transitions?.find((t: any) => {
        const fromStates = Array.isArray(t.from) ? t.from : [t.from];
        return fromStates.includes(currentStateId) && t.event === eventName;
      });

      const pendingTransition: WorkflowPendingTransition = {
        event: eventName,
        toState: targetTransition?.to ?? instance.getCurrentState(),
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
  const workflows = await fullEntitiesList<any>(executionContext, executionContext.user!, [ENTITY_TYPE_WORKFLOW_DEFINITION]);
  for (const workflow of workflows) {
    if (typeof workflow.workflow_content === 'string') {
      if (workflow.workflow_content.includes(statusTemplateId)) {
        return true;
      }
    } else if (workflow.workflow_content) {
      if (JSON.stringify(workflow.workflow_content).includes(statusTemplateId)) {
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
