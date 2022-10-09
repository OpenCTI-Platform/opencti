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
    streamCollection: (_, { id }, context) => findById(context, context.user, id),
    streamCollections: (_, args, context) => findAll(context, context.user, args),
  },
  StreamCollection: {
    groups: (collection, _, context) => streamCollectionGroups(context, context.user, collection),
  },
  Mutation: {
    streamCollectionAdd: (_, { input }, context) => createStreamCollection(context, context.user, input),
    streamCollectionEdit: (_, { id }, context) => ({
      delete: () => streamCollectionDelete(context, context.user, id),
      fieldPatch: ({ input }) => streamCollectionEditField(context, context.user, id, input),
      contextPatch: ({ input }) => streamCollectionEditContext(context, context.user, id, input),
      contextClean: () => streamCollectionCleanContext(context, context.user, id),
      addGroup: ({ id: groupId }) => createGroupRelation(context, context.user, id, groupId),
      deleteGroup: ({ id: groupId }) => deleteGroupRelation(context, context.user, id, groupId),
    }),
  },
};

export default streamResolvers;
