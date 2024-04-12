import type { Resolvers } from '../../generated/graphql';
import { completeDelete, findAll, findById, restoreDelete } from './deleteOperation-domain';
import { batchLoader } from '../../database/middleware';
import { batchCreator } from '../../domain/user';

const creatorLoader = batchLoader(batchCreator);
const deleteOperationResolvers: Resolvers = {
  Query: {
    deleteOperation: (_, { id }, context) => findById(context, context.user, id),
    deleteOperations: (_, args, context) => findAll(context, context.user, args),
  },
  DeleteOperation: {
    deletedBy: (deleteOperation, _, context) => creatorLoader.load(deleteOperation.user_id, context, context.user),
  },
  Mutation: {
    deleteOperationRestore: (_, { id }, context) => restoreDelete(context, context.user, id),
    deleteOperationConfirm: (_, { id }, context) => completeDelete(context, context.user, id),
  }
};

export default deleteOperationResolvers;
