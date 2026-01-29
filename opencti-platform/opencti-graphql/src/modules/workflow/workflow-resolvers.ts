import type { AuthContext } from '../../types/user';
import { getAllowedNextStatuses, getAllowedTransitions, getWorkflowDefinition, getWorkflowInstance, setWorkflowDefinition, triggerWorkflowEvent } from './workflow-domain';

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
    workflowDefinitionSet: (_: any, { entityType, definition }: { entityType: string, definition: string }, context: AuthContext) => {
      return setWorkflowDefinition(context, context.user!, entityType, definition);
    },
    triggerWorkflowEvent: (_: any, { entityId, eventName }: { entityId: string, eventName: string }, context: AuthContext) => {
      return triggerWorkflowEvent(context, context.user!, entityId, eventName);
    },
  },
};

export default workflowResolvers;
