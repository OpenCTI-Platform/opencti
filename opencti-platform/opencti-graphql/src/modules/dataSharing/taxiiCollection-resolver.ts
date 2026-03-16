import type { EditContext, EditInput, Resolvers, TaxiiCollection, TaxiiCollectionConnection, TaxiiCollectionEditMutations } from '../../generated/graphql';
import type { BasicStoreEntity } from '../../types/store';
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
    taxiiCollection: (_, { id }, context) => findById(context, context.user, id) as unknown as Promise<TaxiiCollection>,
    taxiiCollections: (_, args, context) => findTaxiiCollectionPaginated(context, context.user, args) as unknown as Promise<TaxiiCollectionConnection>,
  },
  TaxiiCollection: {
    authorized_members: (taxii, _, context) => getAuthorizedMembers(context, context.user, taxii as unknown as BasicStoreEntity),
  },
  Mutation: {
    taxiiCollectionAdd: (_, { input }, context) => createTaxiiCollection(context, context.user, input) as unknown as Promise<TaxiiCollection>,
    taxiiCollectionEdit: (_, { id }, context) => ({
      delete: () => taxiiCollectionDelete(context, context.user, id),
      fieldPatch: ({ input }: { input: EditInput[] }) => taxiiCollectionEditField(context, context.user, id, input),
      contextPatch: ({ input }: { input: EditContext }) => taxiiCollectionEditContext(context, context.user, id, input),
      contextClean: () => taxiiCollectionCleanContext(context, context.user, id),
    }) as unknown as TaxiiCollectionEditMutations,
  },
};

export default taxiiCollectionResolvers;
