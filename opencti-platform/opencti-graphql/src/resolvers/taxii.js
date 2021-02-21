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
    taxiiCollection: (_, { id }, { user }) => findById(user, id),
    taxiiCollections: (_, __, { user }) => findAll(user),
  },
  Mutation: {
    taxiiCollectionAdd: (_, { input }, { user }) => createTaxiiCollection(user, input),
    taxiiCollectionEdit: (_, { id }, { user }) => ({
      delete: () => taxiiCollectionDelete(user, id),
      fieldPatch: ({ input }) => taxiiCollectionEditField(user, id, input),
      contextPatch: ({ input }) => taxiiCollectionEditContext(user, id, input),
      contextClean: () => taxiiCollectionCleanContext(user, id),
    }),
  },
};

export default taxiiResolvers;
