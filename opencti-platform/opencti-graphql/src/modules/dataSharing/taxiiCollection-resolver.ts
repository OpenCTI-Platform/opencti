import type { Resolvers } from '../../generated/graphql';
import {
  createTaxiiCollection,
  findById,
  findTaxiiCollectionPaginated,
  taxiiCollectionCleanContext,
  taxiiCollectionDelete,
  taxiiCollectionEditContext,
  taxiiCollectionEditField,
} from './taxiiCollection-domain';
import { getAuthorizedMembers } from '../../utils/authorizedMembers';

const taxiiCollectionResolvers: Resolvers = {
  Query: {
    taxiiCollection: (_, { id }, context) => findById(context, context.user, id),
    taxiiCollections: (_, args, context) => findTaxiiCollectionPaginated(context, context.user, args),
  },
  TaxiiCollection: {
    authorized_members: (taxii, _, context) => getAuthorizedMembers(context, context.user, taxii),
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

export default taxiiCollectionResolvers;
