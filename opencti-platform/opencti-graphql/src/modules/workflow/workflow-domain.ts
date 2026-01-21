import type { AuthContext, AuthUser } from '../../types/user';
import { WorkflowFactory } from './workflow-factory';
import type { WorkflowSchema } from './workflow-schema';
import { storeLoadById } from '../../database/middleware-loader';
import type { BasicStoreEntity } from '../../types/store';

export const triggerWorkflowEvent = async (
  context: AuthContext,
  user: AuthUser,
  entityId: string,
  eventName: string,
  schema?: WorkflowSchema
) => {
  const entity = await storeLoadById(context, user, entityId, 'Stix-Domain-Object') as BasicStoreEntity;
  if (!entity) {
    throw new Error(`Entity with id ${entityId} not found`);
  }

  // Determine current status
  const currentStatusId = entity.x_opencti_workflow_id;
  
  // Create machine instance
  // For now we use the factory with a provided schema or a mock one
  const machine = WorkflowFactory.getInstance(schema, undefined, currentStatusId, { entity, context, user });
  
  const result = await machine.trigger(eventName);
  
  if (result.success) {
    const newState = machine.getCurrentState();
    // In real implementation, we would update the entity here
    // await updateAttribute(context, user, entityId, entity.entity_type, [{ key: 'x_opencti_workflow_id', value: [newState] }]);
    return { success: true, newState };
  }
  
  return { success: false, currentState: machine.getCurrentState(), reason: result.reason };
};
