import {
  addWorkspace,
  duplicateWorkspace,
  findWorkspacePaginated,
  findById,
  generateWidgetExportConfiguration,
  generateWorkspaceExportConfiguration,
  getCurrentUserAccessRight,
  getOwnerId,
  getWorkspacePresets,
  getWorkspaceVariables,
  isDashboardShared,
  objects,
  workspaceCleanContext,
  workspaceDelete,
  workspaceEditAuthorizedMembers,
  workspaceEditContext,
  workspaceEditField,
  workspaceImportConfiguration,
  workspaceImportWidgetConfiguration,
  workspacePresetAdd,
  workspacePresetDelete,
  workspacePresetFieldPatch,
  workspaceVariableAdd,
  workspaceVariableDelete,
  workspaceVariableFieldPatch,
} from './workspace-domain';
import { fetchEditContext } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { ENTITY_TYPE_WORKSPACE } from './workspace-types';
import type { Resolvers } from '../../generated/graphql';
import { getAuthorizedMembers } from '../../utils/authorizedMembers';
import { toStixReportBundle } from './investigation-domain';
import { subscribeToInstanceEvents } from '../../graphql/subscriptionWrapper';
import { loadCreator } from '../../database/members';

const workspaceResolvers: Resolvers = {
  Query: {
    workspace: (_, { id }, context) => findById(context, context.user, id),
    workspaces: (_, args, context) => findWorkspacePaginated(context, context.user, args),
  },
  Workspace: {
    authorizedMembers: (workspace, _, context) => getAuthorizedMembers(context, context.user, workspace),
    currentUserAccessRight: (workspace, _, context) => getCurrentUserAccessRight(context.user, workspace),
    owner: (workspace, _, context) => loadCreator(context, context.user, getOwnerId(workspace)),
    objects: (workspace, args, context) => {
      return objects(context, context.user, workspace, args) as any;
    },
    editContext: (workspace) => fetchEditContext(workspace.id),
    toStixReportBundle: (workspace, _, context) => toStixReportBundle(context, context.user, workspace),
    toConfigurationExport: (workspace, _, context) => generateWorkspaceExportConfiguration(context, context.user, workspace),
    toWidgetExport: (workspace, { widgetId }, context) => generateWidgetExportConfiguration(context, context.user, workspace, widgetId),
    isShared: (workspace, _, context) => isDashboardShared(context, workspace),
    variables: (workspace: any) => getWorkspaceVariables(workspace),
    presets: (workspace: any) => getWorkspacePresets(workspace),
  },
  Mutation: {
    workspaceAdd: (_, { input }, context) => {
      return addWorkspace(context, context.user, input);
    },
    workspaceDuplicate: (_, { input }, context) => {
      return duplicateWorkspace(context, context.user, input);
    },
    workspaceDelete: (_, { id }, context) => {
      return workspaceDelete(context, context.user, id);
    },
    workspaceFieldPatch: (_, { id, input }, context) => {
      return workspaceEditField(context, context.user, id, input);
    },
    workspaceEditAuthorizedMembers: (_, { id, input }, context) => {
      return workspaceEditAuthorizedMembers(context, context.user, id, input);
    },
    workspaceContextPatch: (_, { id, input }, context) => {
      return workspaceEditContext(context, context.user, id, input);
    },
    workspaceContextClean: (_, { id }, context) => {
      return workspaceCleanContext(context, context.user, id);
    },
    workspaceConfigurationImport: (_, { file }, context) => {
      return workspaceImportConfiguration(context, context.user, file);
    },
    workspaceWidgetConfigurationImport: (_, { id, input }, context) => {
      return workspaceImportWidgetConfiguration(context, context.user, id, input);
    },
    /* eslint-disable @typescript-eslint/no-explicit-any */
    workspaceVariableAdd: ((_: any, { id, input }: any, context: any) => {
      return workspaceVariableAdd(context, context.user, id, input);
    }) as any,
    workspaceVariableFieldPatch: ((_: any, { id, variableId, input }: any, context: any) => {
      return workspaceVariableFieldPatch(context, context.user, id, variableId, input);
    }) as any,
    workspaceVariableDelete: ((_: any, { id, variableId }: any, context: any) => {
      return workspaceVariableDelete(context, context.user, id, variableId);
    }) as any,
    workspacePresetAdd: ((_: any, { id, input }: any, context: any) => {
      return workspacePresetAdd(context, context.user, id, input);
    }) as any,
    workspacePresetFieldPatch: ((_: any, { id, presetId, input }: any, context: any) => {
      return workspacePresetFieldPatch(context, context.user, id, presetId, input);
    }) as any,
    workspacePresetDelete: ((_: any, { id, presetId }: any, context: any) => {
      return workspacePresetDelete(context, context.user, id, presetId);
    }) as any,
    /* eslint-enable @typescript-eslint/no-explicit-any */
  },
  Subscription: {
    workspace: {
      resolve: /* v8 ignore next */ (payload: any) => payload.instance,
      subscribe: /* v8 ignore next */ (_, { id }, context) => {
        const bus = BUS_TOPICS[ENTITY_TYPE_WORKSPACE];
        return subscribeToInstanceEvents(_, context, id, [bus.EDIT_TOPIC], { type: ENTITY_TYPE_WORKSPACE });
      },
    },
  },
};

export default workspaceResolvers;
