import type { EditContext, EditInput, Resolvers } from '../../generated/graphql';
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
import { loadCreator } from '../../database/members';

const taxiiCollectionResolvers: Resolvers = {
  Query: {
    taxiiCollection: (_, { id }, context) => findById(context, context.user, id),
    taxiiCollections: (_, args, context) => findTaxiiCollectionPaginated(context, context.user, args),
  },
  TaxiiCollection: {
    authorized_members: (taxii, _, context) => getAuthorizedMembers(context, context.user, taxii),
    taxii_public_user: (taxii, _, context) => taxii.taxii_public_user_id ? loadCreator(context, context.user, taxii.taxii_public_user_id) : null,
  },
  Mutation: {
    taxiiCollectionAdd: (_, { input }, context) => createTaxiiCollection(context, context.user, input),
    taxiiCollectionEdit: (_, { id }, context) => ({
      delete: () => taxiiCollectionDelete(context, context.user, id),
      fieldPatch: ({ input }: { input: EditInput[] }) => taxiiCollectionEditField(context, context.user, id, input),
      contextPatch: ({ input }: { input: EditContext }) => taxiiCollectionEditContext(context, context.user, id, input),
      contextClean: () => taxiiCollectionCleanContext(context, context.user, id),
    }) as any,
  },
};

export default taxiiCollectionResolvers;
