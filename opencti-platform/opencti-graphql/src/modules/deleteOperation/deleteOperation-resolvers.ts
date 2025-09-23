import type { Resolvers } from '../../generated/graphql';
import { findDeleteOperationPaginated, findById, restoreDelete, confirmDelete } from './deleteOperation-domain';

const deleteOperationResolvers: Resolvers = {
  Query: {
    deleteOperation: (_, { id }, context) => findById(context, context.user, id),
    deleteOperations: (_, args, context) => findDeleteOperationPaginated(context, context.user, args),
  },
  DeleteOperation: {
    objectMarking: (deleteOperation, _, context) => context.batch.markingsBatchLoader.load(deleteOperation),
    deletedBy: (deleteOperation, _, context) => context.batch.creatorBatchLoader.load(deleteOperation.creator_id?.[0]),
  },
  Mutation: {
    deleteOperationRestore: (_, { id }, context) => restoreDelete(context, context.user, id),
    deleteOperationConfirm: (_, { id }, context) => confirmDelete(context, context.user, id),
  }
};

export default deleteOperationResolvers;
