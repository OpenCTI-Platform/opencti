import { BYPASS } from '../../utils/access';
import type { Context } from './workflow-types';

export type ConditionFunction<TContext extends Context = Context> = (ctx: TContext, params?: any) => Promise<boolean> | boolean;

export const ConditionRegistry: Record<string, ConditionFunction> = {
  // generic conditions examples:
  isAdmin: (ctx) => {
    return ctx.user.capabilities?.some((c: any) => c?.name === BYPASS) || false;
  },
  hasCapability: (ctx, params) => {
    const capability = params?.capability;
    return ctx.user?.capabilities?.some((c: any) => c.name === capability) || false;
  },
};
