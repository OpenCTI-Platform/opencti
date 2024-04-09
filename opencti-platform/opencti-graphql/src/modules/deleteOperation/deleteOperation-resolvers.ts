import type { Resolvers } from '../../generated/graphql';
import { findAll, findById, restoreDelete, confirmDelete } from './deleteOperation-domain';
import { batchLoader } from '../../database/middleware';
import { batchCreator } from '../../domain/user';
import { batchMarkingDefinitions } from '../../domain/stixCoreObject';

const markingDefinitionsLoader = batchLoader(batchMarkingDefinitions);
const creatorLoader = batchLoader(batchCreator);

const deleteOperationResolvers: Resolvers = {
  Query: {
    deleteOperation: (_, { id }, context) => findById(context, context.user, id),
    deleteOperations: (_, args, context) => findAll(context, context.user, args),
  },
  DeleteOperation: {
    objectMarking: (deleteOperation, _, context) => markingDefinitionsLoader.load(deleteOperation, context, context.user),
    deletedBy: (deleteOperation, _, context) => creatorLoader.load(deleteOperation.creator_id?.[0], context, context.user),
  },
  Mutation: {
    deleteOperationRestore: (_, { id }, context) => restoreDelete(context, context.user, id),
    deleteOperationConfirm: (_, { id }, context) => confirmDelete(context, context.user, id),
  }
};

export default deleteOperationResolvers;
