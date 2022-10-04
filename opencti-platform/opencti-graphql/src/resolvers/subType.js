import { findAll, findById } from '../domain/subType';
import { createStatus, getTypeStatuses, statusDelete, statusEditField } from '../domain/status';

const subTypeResolvers = {
  Query: {
    subType: (_, { id }) => findById(id),
    subTypes: (_, args) => findAll(args),
  },
  SubType: {
    workflowEnabled: async (current, _, context) => {
      const statusesEdges = await getTypeStatuses(context, context.user, current.label);
      return statusesEdges.edges.length > 0;
    },
    statuses: (current, _, context) => getTypeStatuses(context, context.user, current.id),
  },
  Mutation: {
    subTypeEdit: (_, { id }, context) => ({
      statusAdd: ({ input }) => createStatus(context, context.user, id, input),
      statusFieldPatch: ({ statusId, input }) => statusEditField(context, context.user, id, statusId, input),
      statusDelete: ({ statusId }) => statusDelete(context, context.user, id, statusId),
    }),
  },
};

export default subTypeResolvers;
