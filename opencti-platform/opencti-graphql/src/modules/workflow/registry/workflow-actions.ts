import { logApp } from '../../../config/conf';
import { draftWorkspaceEditAuthorizedMembers, validateDraftWorkspace } from '../../draftWorkspace/draftWorkspace-domain';
import type { Context } from '../types/workflow-types';
import { z } from 'zod';

export type ActionFunction<TContext extends Context = Context> = (executionContext: TContext, params?: any) => Promise<void> | void;

export interface ActionDefinition {
  fn: ActionFunction;
  paramsSchema?: z.ZodTypeAny;
  allowedModes?: ('sync' | 'async')[];
}

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
    const { entity, user, context } = executionContext;
    await draftWorkspaceEditAuthorizedMembers(context, user, entity.id, params?.authorized_members);
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
      })).optional(),
    }).optional(),
    allowedModes: ['sync', 'async'],
  },
};
