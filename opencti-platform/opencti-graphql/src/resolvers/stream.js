import {
  findById,
  findAll,
  createStreamCollection,
  streamCollectionDelete,
  streamCollectionEditField,
  streamCollectionEditContext,
  streamCollectionCleanContext,
} from '../domain/stream';

const streamResolvers = {
  Query: {
    streamCollection: (_, { id }, { user }) => findById(user, id),
    streamCollections: (_, args, { user }) => findAll(user, args),
  },
  Mutation: {
    streamCollectionAdd: (_, { input }, { user }) => createStreamCollection(user, input),
    streamCollectionEdit: (_, { id }, { user }) => ({
      delete: () => streamCollectionDelete(user, id),
      fieldPatch: ({ input }) => streamCollectionEditField(user, id, input),
      contextPatch: ({ input }) => streamCollectionEditContext(user, id, input),
      contextClean: () => streamCollectionCleanContext(user, id),
    }),
  },
};

export default streamResolvers;
