import { addIngestion, findAllPaginated, findById, ingestionDelete, ingestionEditField, } from './ingestion-rss-domain';
import type { Resolvers } from '../../generated/graphql';

const ingestionRssResolvers: Resolvers = {
  Query: {
    rssIngestion: (_, { id }, context) => findById(context, context.user, id),
    rssIngestions: (_, args, context) => findAllPaginated(context, context.user, args),
  },
  Mutation: {
    rssIngestionAdd: (_, { input }, context) => {
      return addIngestion(context, context.user, input);
    },
    rssIngestionDelete: (_, { id }, context) => {
      return ingestionDelete(context, context.user, id);
    },
    rssIngestionFieldPatch: (_, { id, input }, context) => {
      return ingestionEditField(context, context.user, id, input);
    },
  },
};

export default ingestionRssResolvers;
