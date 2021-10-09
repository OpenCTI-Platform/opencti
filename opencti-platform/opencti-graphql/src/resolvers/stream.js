import {
  findById,
  findAll,
  createStreamCollection,
  streamCollectionDelete,
  streamCollectionEditField,
  streamCollectionEditContext,
  streamCollectionCleanContext,
  streamCollectionGroups,
  createGroupRelation,
  deleteGroupRelation,
} from '../domain/stream';

const streamResolvers = {
  Query: {
    streamCollection: (_, { id }, { user }) => findById(user, id),
    streamCollections: (_, args, { user }) => findAll(user, args),
  },
  StreamCollection: {
    groups: (collection, _, { user }) => streamCollectionGroups(user, collection),
  },
  Mutation: {
    streamCollectionAdd: (_, { input }, { user }) => createStreamCollection(user, input),
    streamCollectionEdit: (_, { id }, { user }) => ({
      delete: () => streamCollectionDelete(user, id),
      fieldPatch: ({ input }) => streamCollectionEditField(user, id, input),
      contextPatch: ({ input }) => streamCollectionEditContext(user, id, input),
      contextClean: () => streamCollectionCleanContext(user, id),
      addGroup: ({ id: groupId }) => createGroupRelation(user, id, groupId),
      deleteGroup: ({ id: groupId }) => deleteGroupRelation(user, id, groupId),
    }),
  },
};

export default streamResolvers;
