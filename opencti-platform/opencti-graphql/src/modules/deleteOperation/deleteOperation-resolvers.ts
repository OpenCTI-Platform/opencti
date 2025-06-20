import type { Resolvers } from '../../generated/graphql';
import { findAll, findById, restoreDelete, confirmDelete } from './deleteOperation-domain';

const deleteOperationResolvers: Resolvers = {
  Query: {
    deleteOperation: (_, { id }, context) => findById(context, context.user, id),
    deleteOperations: (_, args, context) => findAll(context, context.user, args),
  },
  DeleteOperation: {
    objectMarking: (deleteOperation, _, context) => context.markingsBatchLoader.load(deleteOperation),
    deletedBy: (deleteOperation, _, context) => context.creatorBatchLoader.load(deleteOperation.creator_id?.[0]),
  },
  Mutation: {
    deleteOperationRestore: (_, { id }, context) => restoreDelete(context, context.user, id),
    deleteOperationConfirm: (_, { id }, context) => confirmDelete(context, context.user, id),
  }
};

export default deleteOperationResolvers;
