import { addIngestion, findRssIngestionPaginated, findById, ingestionDelete, ingestionEditField, } from './ingestion-rss-domain';
import type { Resolvers } from '../../generated/graphql';
import { storeLoadByIds } from '../../database/middleware-loader';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../schema/stixMetaObject';
import type { BasicStoreEntityMarkingDefinition } from '../../types/store';
import { ENTITY_TYPE_IDENTITY } from '../../schema/general';

const ingestionRssResolvers: Resolvers = {
  Query: {
    ingestionRss: (_, { id }, context) => findById(context, context.user, id),
    ingestionRsss: (_, args, context) => findRssIngestionPaginated(context, context.user, args),
  },
  IngestionRss: {
    defaultCreatedBy: (ingestionRss, _, context) => context.batch.idsBatchLoader.load({ id: ingestionRss.created_by_ref, type: ENTITY_TYPE_IDENTITY }),
    // eslint-disable-next-line max-len
    defaultMarkingDefinitions: (ingestionRss, _, context) => storeLoadByIds<BasicStoreEntityMarkingDefinition>(context, context.user, ingestionRss.object_marking_refs ?? [], ENTITY_TYPE_MARKING_DEFINITION),
    user: (ingestionRss, _, context) => context.batch.creatorBatchLoader.load(ingestionRss.user_id),
  },
  Mutation: {
    ingestionRssAdd: (_, { input }, context) => {
      return addIngestion(context, context.user, input);
    },
    ingestionRssDelete: (_, { id }, context) => {
      return ingestionDelete(context, context.user, id);
    },
    ingestionRssFieldPatch: (_, { id, input }, context) => {
      return ingestionEditField(context, context.user, id, input);
    },
  },
};

export default ingestionRssResolvers;
