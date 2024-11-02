import {
  addWorkspace,
  duplicateWorkspace,
  findAll,
  findById,
  generateWidgetExportConfiguration,
  generateWorkspaceExportConfiguration,
  getCurrentUserAccessRight,
  getOwnerId,
  isDashboardShared,
  objects,
  workspaceCleanContext,
  workspaceDelete,
  workspaceEditAuthorizedMembers,
  workspaceEditContext,
  workspaceEditField,
  workspaceImportConfiguration,
  workspaceImportWidgetConfiguration
} from './workspace-domain';
import { fetchEditContext } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { ENTITY_TYPE_WORKSPACE } from './workspace-types';
import type { Resolvers } from '../../generated/graphql';
import { batchLoader } from '../../database/middleware';
import { batchCreator } from '../../domain/user';
import { getAuthorizedMembers } from '../../utils/authorizedMembers';
import { toStixReportBundle } from './investigation-domain';
import { subscribeToInstanceEvents } from '../../graphql/subscriptionWrapper';

const creatorLoader = batchLoader(batchCreator);

const workspaceResolvers: Resolvers = {
  Query: {
    workspace: (_, { id }, context) => findById(context, context.user, id),
    workspaces: (_, args, context) => findAll(context, context.user, args),
  },
  Workspace: {
    authorizedMembers: (workspace, _, context) => getAuthorizedMembers(context, context.user, workspace),
    currentUserAccessRight: (workspace, _, context) => getCurrentUserAccessRight(context, context.user, workspace),
    owner: (workspace, _, context) => creatorLoader.load(getOwnerId(workspace), context, context.user),
    objects: (workspace, args, context) => objects(context, context.user, workspace, args),
    editContext: (workspace) => fetchEditContext(workspace.id),
    toStixReportBundle: (workspace, _, context) => toStixReportBundle(context, context.user, workspace),
    toConfigurationExport: (workspace, _, context) => generateWorkspaceExportConfiguration(context, context.user, workspace),
    toWidgetExport: (workspace, { widgetId }, context) => generateWidgetExportConfiguration(context, context.user, workspace, widgetId),
    isShared: (workspace, _, context) => isDashboardShared(context, workspace)
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
