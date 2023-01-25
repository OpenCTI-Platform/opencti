import { findAll, findById as findSubTypeById, findById } from '../domain/subType';
import { createStatus, getTypeStatuses, statusDelete, statusEditField } from '../domain/status';
import { findByType } from '../modules/entitySetting/entitySetting-domain';
import { queryMandatoryAttributes } from '../domain/attribute';

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
    settings: (current, _, context) => findByType(context, context.user, current.id),
    mandatoryAttributes: (current, _, context) => queryMandatoryAttributes(context, current.id),
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
