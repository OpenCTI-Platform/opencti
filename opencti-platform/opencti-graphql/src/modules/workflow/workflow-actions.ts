import { logApp } from '../../config/conf';
import { validateDraftWorkspace } from '../draftWorkspace/draftWorkspace-domain';
import type { Context } from './workflow-types';

export type ActionFunction<TContext extends Context = Context> = (ctx: TContext, params?: any) => Promise<void> | void;

export const ActionRegistry: Record<string, ActionFunction> = {
  // actions examples:
  log: async (ctx, params) => {
    // eslint-disable-next-line no-console
    logApp.info(`[Action: LOG] Context: ${JSON.stringify(ctx)} | Message: ${params?.message || 'No message'}`);
  },
  validateDraft: async (ctx) => {
    const { entity, user, context } = ctx;
    await validateDraftWorkspace(context, user, entity.id);
  },
};
