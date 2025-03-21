import { findAll, findById as findSubTypeById, findById } from '../domain/subType';
import { batchGlobalStatusesByType, batchRequestAccessStatusesByType, createStatus, getTypeStatuses, statusDelete, statusEditField } from '../domain/status';
import { batchEntitySettingsByType } from '../modules/entitySetting/entitySetting-domain';
import { batchLoader } from '../database/middleware';

const statusesGlobalByTypeLoader = batchLoader(batchGlobalStatusesByType);
const statusesRequestAccessByTypeLoader = batchLoader(batchRequestAccessStatusesByType);
const entitySettingsByTypeLoader = batchLoader(batchEntitySettingsByType);

const subTypeResolvers = {
  Query: {
    subType: (_, { id }) => findById(id),
    subTypes: (_, args, context) => findAll(context, context.user, args),
  },
  SubType: {
    workflowEnabled: async (current, _, context) => {
      const statusesEdges = await getTypeStatuses(context, context.user, current.label);
      return statusesEdges.edges.length > 0;
    },
    statuses: (current, _, context) => statusesGlobalByTypeLoader.load(current.id, context, context.user),
    statusesRequestAccess: (current, _, context) => statusesRequestAccessByTypeLoader.load(current.id, context, context.user),
    settings: (current, _, context) => entitySettingsByTypeLoader.load(current.id, context, context.user), // Simpler before moving workflow
  },
  Mutation: {
    subTypeEdit: (_, { id }, context) => ({
      statusAdd: ({ input }) => createStatus(context, context.user, id, input).then(() => findSubTypeById(id)),
      statusFieldPatch: ({ statusId, input }) => statusEditField(context, context.user, id, statusId, input),
      statusDelete: ({ statusId }) => statusDelete(context, context.user, id, statusId),
    }),
  },
};

export default subTypeResolvers;
