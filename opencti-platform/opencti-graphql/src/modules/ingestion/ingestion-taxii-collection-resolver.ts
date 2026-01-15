import { addIngestion, findTaxiiCollectionPaginated, findById, ingestionDelete, ingestionEditField } from './ingestion-taxii-collection-domain';
import type { Resolvers } from '../../generated/graphql';
import { getAuthorizedMembers } from '../../utils/authorizedMembers';
import { redisGetConnectorHistory } from '../../database/redis';
import { type BasicStoreEntityIngestionTaxiiCollection } from './ingestion-types';

const ingestionTaxiiCollectionResolvers: Resolvers = {
  Query: {
    ingestionTaxiiCollection: (_, { id }, context) => findById(context, context.user, id),
    ingestionTaxiiCollections: (_, args, context) => findTaxiiCollectionPaginated(context, context.user, args),
  },
  IngestionTaxiiCollection: {
    user: (ingestionTaxiiCollection: BasicStoreEntityIngestionTaxiiCollection, _, context) => context.batch.creatorBatchLoader.load(ingestionTaxiiCollection.user_id),
    authorized_members: (ingestionTaxiiCollection: BasicStoreEntityIngestionTaxiiCollection, _, context) => getAuthorizedMembers(context, context.user, ingestionTaxiiCollection),
    ingestionLogs: (ingestionTaxiiCollection: BasicStoreEntityIngestionTaxiiCollection) => redisGetConnectorHistory(ingestionTaxiiCollection.internal_id),
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
