import {
  findById,
  findAll,
  createStreamCollection,
  streamCollectionDelete,
  streamCollectionEditField,
  streamCollectionEditContext,
  streamCollectionCleanContext,
} from '../domain/stream';
import { getAuthorizedMembers } from '../utils/authorizedMembers';

const streamResolvers = {
  Query: {
    streamCollection: (_, { id }, context) => findById(context, context.user, id),
    streamCollections: (_, args, context) => findAll(context, context.user, args),
  },
  StreamCollection: {
    authorized_members: (stream, _, context) => getAuthorizedMembers(context, context.user, stream),
  },
  Mutation: {
    streamCollectionAdd: (_, { input }, context) => createStreamCollection(context, context.user, input),
    streamCollectionEdit: (_, { id }, context) => ({
      delete: () => streamCollectionDelete(context, context.user, id),
      fieldPatch: ({ input }) => streamCollectionEditField(context, context.user, id, input),
      contextPatch: ({ input }) => streamCollectionEditContext(context, context.user, id, input),
      contextClean: () => streamCollectionCleanContext(context, context.user, id),
    }),
  },
};

export default streamResolvers;
