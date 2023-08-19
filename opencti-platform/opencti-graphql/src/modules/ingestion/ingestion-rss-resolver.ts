import { addIngestion, findAllPaginated, findById, ingestionDelete, ingestionEditField, } from './ingestion-rss-domain';
import type { Creator, Identity, MarkingDefinition, Resolvers } from '../../generated/graphql';
import { storeLoadById } from '../../database/middleware-loader';
import { ENTITY_TYPE_IDENTITY } from '../../schema/general';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../schema/stixMetaObject';
import { ENTITY_TYPE_USER } from '../../schema/internalObject';

const ingestionRssResolvers: Resolvers = {
  Query: {
    ingestionRss: (_, { id }, context) => findById(context, context.user, id),
    ingestionRsss: (_, args, context) => findAllPaginated(context, context.user, args),
  },
  IngestionRss: {
    // eslint-disable-next-line max-len
    created_by: (ingestionRss, _, context) => (ingestionRss.created_by_ref ? storeLoadById(context, context.user, ingestionRss.created_by_ref, ENTITY_TYPE_IDENTITY) as unknown as Identity : null),
    object_marking: (ingestionRss, _, context) => ingestionRss.object_marking_refs?.map(
      (id: string) => storeLoadById(context, context.user, id, ENTITY_TYPE_MARKING_DEFINITION) as unknown as MarkingDefinition,
    ),
    user: (ingestionRss, _, context) => (ingestionRss.user_id ? storeLoadById(context, context.user, ingestionRss.user_id, ENTITY_TYPE_USER) as unknown as Creator : null),
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
