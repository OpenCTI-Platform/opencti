import { findSubTypePaginated, findById as findSubTypeById, findById } from '../domain/subType';
import { createStatus, isGlobalWorkflowEnabled, statusDelete, statusEditField } from '../domain/status';

const subTypeResolvers = {
  Query: {
    subType: (_, { id }) => findById(id),
    subTypes: (_, args, context) => findSubTypePaginated(context, context.user, args),
  },
  SubType: {
    workflowEnabled: (current, _, context) => isGlobalWorkflowEnabled(context, context.user, current.id),
    statuses: (current, _, context) => context.batch.globalStatusBatchLoader.load(current.id),
    statusesRequestAccess: (current, _, context) => context.batch.requestAccessStatusBatchLoader.load(current.id),
    settings: (current, _, context) => context.batch.entitySettingsBatchLoader.load(current.id), // Simpler before moving workflow
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
