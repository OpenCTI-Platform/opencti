import type { Resolvers } from '../../generated/graphql';
import { completeDelete, findAll, findById, restoreDelete } from './deleteOperation-domain';

const deleteOperationResolvers: Resolvers = {
  Query: {
    deleteOperation: (_, { id }, context) => findById(context, context.user, id),
    deleteOperations: (_, args, context) => findAll(context, context.user, args),
  },
  Mutation: {
    deleteOperationRestore: (_, { id }, context) => {
      return restoreDelete(context, context.user, id);
    },
    deleteOperationConfirm: (_, { id }, context) => {
      return completeDelete(context, context.user, id);
    },
  }
};

export default deleteOperationResolvers;
