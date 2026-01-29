import { FunctionalError } from '../../config/errors';
import { createEntity, createRelation, updateAttribute } from '../../database/middleware';
import { fullRelationsList, storeLoadById } from '../../database/middleware-loader';
import { findById as findStatusById } from '../../domain/status';
import { RELATION_HAS_WORKFLOW } from '../../schema/internalRelationship';
import type { AuthContext, AuthUser } from '../../types/user';
import { findByType as findEntitySettingByType } from '../entitySetting/entitySetting-domain';
import { WorkflowFactory } from './workflow-factory';
import { ENTITY_TYPE_WORKFLOW_DEFINITION, ENTITY_TYPE_WORKFLOW_INSTANCE, type TriggerResult } from './workflow-types';

const getWorkflowConfig = async (context: AuthContext, user: AuthUser, targetType: string) => {
  return findEntitySettingByType(context, user, targetType);
};

const getDefinitionData = async (context: AuthContext, user: AuthUser, entitySetting: any) => {
  if (!entitySetting) return null;

  if (entitySetting.workflow_id) {
    const workflowDefinitionEntity = await storeLoadById(context, user, entitySetting.workflow_id, ENTITY_TYPE_WORKFLOW_DEFINITION) as any;
    if (workflowDefinitionEntity) {
      return typeof workflowDefinitionEntity.workflow_content === 'string'
        ? JSON.parse(workflowDefinitionEntity.workflow_content)
        : workflowDefinitionEntity.workflow_content;
    }
  }

  return null;
};

const findWorkflowInstanceEntity = async (
  context: AuthContext,
  user: AuthUser,
  entityId: string,
) => {
  // Find existing instance via relationship
  const relations = await fullRelationsList(context, user, RELATION_HAS_WORKFLOW, {
    fromId: entityId,
    toTypes: [ENTITY_TYPE_WORKFLOW_INSTANCE],
  });

  if (relations.length > 0) {
    return await storeLoadById(context, user, (relations[0] as any).toId, ENTITY_TYPE_WORKFLOW_INSTANCE) as any;
  }

  return null;
};

const initializeWorkflowInstance = async (
  context: AuthContext,
  user: AuthUser,
  entity: any,
  entitySetting: any,
  definitionData: any,
) => {
  const initialState = definitionData.initialState;
  const instanceInput = {
    workflow_id: entitySetting.workflow_id || 'manual',
    currentState: initialState,
    history: JSON.stringify([{
      state: initialState,
      user_id: user.id,
      timestamp: new Date().toISOString(),
      event: 'initialization',
    }]),
  };
  const instance = await createEntity(context, user, instanceInput, ENTITY_TYPE_WORKFLOW_INSTANCE);

  await createRelation(context, user, {
    fromId: entity.id,
    toId: instance.id,
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

  // Validate definition is valid JSON
  let definitionObj;
  try {
    definitionObj = JSON.parse(definition);
  } catch (_error) {
    throw FunctionalError('Invalid workflow definition JSON');
  }

  const workflowName = definitionObj.name || `Workflow for ${entityType}`;

  // 1. Check if we have an existing workflow linked
  if (entitySetting.workflow_id) {
    const existingWorkflow = await storeLoadById(context, user, entitySetting.workflow_id, ENTITY_TYPE_WORKFLOW_DEFINITION);
    if (existingWorkflow) {
      await updateAttribute(context, user, existingWorkflow.id, ENTITY_TYPE_WORKFLOW_DEFINITION, [
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
  const workflowDefinition = await createEntity(context, user, workflowDefinitionInput, ENTITY_TYPE_WORKFLOW_DEFINITION);

  // 3. Link it to the EntitySetting
  const { element } = await updateAttribute(context, user, entitySetting.id, 'EntitySetting', [
    { key: 'workflow_id', value: [workflowDefinition.id] },
  ]);
  return element;
};

/**
 * Get workflow instance for an entity.
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

  const instanceEntity = await findWorkflowInstanceEntity(context, user, entity.id);
  const currentState = instanceEntity?.currentState ?? definitionData.initialState;

  const allowedTransitions = await getAllowedTransitions(context, user, entityId);
  return {
    currentState: currentState || '',
    allowedTransitions,
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

  const instanceEntity = await findWorkflowInstanceEntity(context, user, entity.id);
  const currentStateId = instanceEntity?.currentState ?? definitionData.initialState;

  const definition = WorkflowFactory.createDefinition(definitionData);
  const effectiveStateId = currentStateId || definition.getInitialState();
  if (!effectiveStateId || !definition.hasState(effectiveStateId)) {
    return [];
  }

  const transitions = definition.getTransitions(effectiveStateId);

  const resolvedTransitions = await Promise.all(transitions.map(async (t) => {
    const status = await findStatusById(context, user, t.to);
    return {
      event: t.event,
      toState: t.to,
      toStatus: status,
    };
  }));

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
  return transitions.map((t) => t.toStatus).filter((s) => s !== null && s !== undefined);
};

/**
 * Trigger a workflow event on an entity.
 * This is the main entry point for the backend logic.
 *
 * @param context The auth context
 * @param user The auth user
 * @param entityId The ID of the entity to trigger the event on
 * @param eventName The name of the event to trigger
 * @returns {Promise<TriggerResult>} The result of the trigger
 */
export const triggerWorkflowEvent = async (
  context: AuthContext,
  user: AuthUser,
  entityId: string,
  eventName: string,
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
    const workflowContext = {
      entity,
      user,
      context,
    };

    let instanceEntity = await findWorkflowInstanceEntity(context, user, entity.id);
    if (!instanceEntity) {
      instanceEntity = await initializeWorkflowInstance(context, user, entity, entitySetting, definitionData);
    }
    const currentStateId = instanceEntity.currentState;

    const definition = WorkflowFactory.createDefinition(definitionData);

    // 5. Create instance and Trigger the event
    const instance = WorkflowFactory.getInstance(definitionData, definition, currentStateId || '', workflowContext);
    const result = await instance.trigger(eventName);

    // 6. If successful, update the database
    if (result.success) {
      const newState = instance.getCurrentState();

      // Update the instance entity
      const history = JSON.parse(instanceEntity.history || '[]');
      history.push({
        state: newState,
        user_id: user.id,
        timestamp: new Date().toISOString(),
        event: eventName,
      });
      await updateAttribute(context, user, instanceEntity.id, ENTITY_TYPE_WORKFLOW_INSTANCE, [
        { key: 'currentState', value: [newState] },
        { key: 'history', value: [JSON.stringify(history)] },
      ]);

      const status = await findStatusById(context, user, newState);
      return { success: true, newState, status };
    }

    return result;
  } catch (error) {
    const reason = error instanceof Error ? error.message : 'Unknown error';
    return {
      success: false,
      reason: `Workflow execution failed: ${reason}`,
    };
  }
};
