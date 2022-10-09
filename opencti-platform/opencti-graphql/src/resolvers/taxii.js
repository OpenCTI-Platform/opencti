import {
  findById,
  findAll,
  createTaxiiCollection,
  taxiiCollectionDelete,
  taxiiCollectionEditField,
  taxiiCollectionEditContext,
  taxiiCollectionCleanContext,
} from '../domain/taxii';

const taxiiResolvers = {
  Query: {
    taxiiCollection: (_, { id }, context) => findById(context, context.user, id),
    taxiiCollections: (_, args, context) => findAll(context, context.user, args),
  },
  Mutation: {
    taxiiCollectionAdd: (_, { input }, context) => createTaxiiCollection(context, context.user, input),
    taxiiCollectionEdit: (_, { id }, context) => ({
      delete: () => taxiiCollectionDelete(context, context.user, id),
      fieldPatch: ({ input }) => taxiiCollectionEditField(context, context.user, id, input),
      contextPatch: ({ input }) => taxiiCollectionEditContext(context, context.user, id, input),
      contextClean: () => taxiiCollectionCleanContext(context, context.user, id),
    }),
  },
};

export default taxiiResolvers;
