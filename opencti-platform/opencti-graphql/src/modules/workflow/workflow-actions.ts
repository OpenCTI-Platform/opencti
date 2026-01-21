import type { Context } from './workflow-types';

export type ActionFunction<TContext extends Context = Context> = (ctx: TContext, params?: any) => Promise<void> | void;

export const ActionRegistry: Record<string, ActionFunction> = {
  log: async (ctx, params) => {
    // eslint-disable-next-line no-console
    console.log(`[Action: LOG] Context: ${JSON.stringify(ctx)} | Message: ${params?.message || 'No message'}`);
  },
};
