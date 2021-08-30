import { findAll, findById } from '../domain/subType';
import { createStatus, getTypeStatuses, statusDelete, statusEditField } from '../domain/status';

const subTypeResolvers = {
  Query: {
    subType: (_, { id }) => findById(id),
    subTypes: (_, args) => findAll(args),
  },
  SubType: {
    workflowEnabled: async (current, _, { user }) => {
      const statusesEdges = await getTypeStatuses(user, current.label);
      return statusesEdges.edges.length > 0;
    },
    statuses: (current, _, { user }) => getTypeStatuses(user, current.id),
  },
  Mutation: {
    subTypeEdit: (_, { id }, { user }) => ({
      statusAdd: ({ input }) => createStatus(user, id, input),
      statusFieldPatch: ({ statusId, input }) => statusEditField(user, id, statusId, input),
      statusDelete: ({ statusId }) => statusDelete(user, id, statusId),
    }),
  },
};

export default subTypeResolvers;
