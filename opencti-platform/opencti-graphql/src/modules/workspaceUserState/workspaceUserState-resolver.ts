/* eslint-disable @typescript-eslint/no-explicit-any */
import type { Resolvers } from '../../generated/graphql';
import { myDashboardVariableState, workspacePresetApply, workspaceVariableResetValue, workspaceVariableSetValue } from './workspaceUserState-domain';

const workspaceUserStateResolvers: Resolvers = {
  Query: {
    myDashboardVariableState: ((_: any, { workspaceId }: any, context: any) => myDashboardVariableState(context, context.user, workspaceId)) as any,
  },
  Mutation: {
    workspaceVariableSetValue: ((_: any, { workspaceId, variableId, value }: any, context: any) => {
      return workspaceVariableSetValue(context, context.user, workspaceId, variableId, value);
    }) as any,
    workspaceVariableResetValue: ((_: any, { workspaceId, variableId }: any, context: any) => {
      return workspaceVariableResetValue(context, context.user, workspaceId, variableId);
    }) as any,
    workspacePresetApply: ((_: any, { workspaceId, presetId }: any, context: any) => {
      return workspacePresetApply(context, context.user, workspaceId, presetId);
    }) as any,
  },
};
/* eslint-enable @typescript-eslint/no-explicit-any */

export default workspaceUserStateResolvers;
