import { addIngestion, findAllPaginated, findById, ingestionDelete, ingestionEditField } from './ingestion-taxii-collection-domain';
import type { Resolvers } from '../../generated/graphql';
import { batchCreator } from '../../domain/user';
import { batchLoader } from '../../database/middleware';
import { getAuthorizedMembers } from '../../utils/authorizedMembers';

const creatorLoader = batchLoader(batchCreator);

const ingestionTaxiiCollectionResolvers: Resolvers = {
  Query: {
    ingestionTaxiiCollection: (_, { id }, context) => findById(context, context.user, id),
    ingestionTaxiiCollections: (_, args, context) => findAllPaginated(context, context.user, args),
  },
  IngestionTaxiiCollection: {
    user: (ingestionTaxiiCollection, _, context) => creatorLoader.load(ingestionTaxiiCollection.user_id, context, context.user),
    authorized_members: (ingestionTaxiiCollection, _, context) => getAuthorizedMembers(context, context.user, ingestionTaxiiCollection),
  },
  Mutation: {
    ingestionTaxiiCollectionAdd: (_, { input }, context) => {
      return addIngestion(context, context.user, input);
    },
    ingestionTaxiiCollectionDelete: (_, { id }, context) => {
      return ingestionDelete(context, context.user, id);
    },
    ingestionTaxiiCollectionFieldPatch: (_, { id, input }, context) => {
      return ingestionEditField(context, context.user, id, input);
    },
  },
};

export default ingestionTaxiiCollectionResolvers;
