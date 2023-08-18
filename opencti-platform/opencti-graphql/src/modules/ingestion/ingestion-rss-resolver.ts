import { addIngestion, findAllPaginated, findById, ingestionDelete, ingestionEditField, } from './ingestion-rss-domain';
import type { Resolvers } from '../../generated/graphql';
import { findById as findIdentityById } from '../../domain/identity';
import { findById as findMarkingDefinitionById } from '../../domain/markingDefinition';
import { findById as findUserById } from '../../domain/user';
import type { BasicStoreEntityIngestionRss } from './ingestion-types';
import type { AuthContext } from '../../types/user';

const ingestionRssResolvers: Resolvers = {
  Query: {
    ingestionRss: (_, { id }, context) => findById(context, context.user, id),
    ingestionRsss: (_, args, context) => findAllPaginated(context, context.user, args),
  },
  IngestionRss: {
    created_by: (ingestionRss, _, context: AuthContext) => findIdentityById(context, context.user, ingestionRss.created_by_ref),
    object_marking: (ingestionRss, _, context: AuthContext) => ingestionRss.object_marking_refs?.map(
      (id: string) => findMarkingDefinitionById(context, context.user, id)
    ),
    user: (ingestionRss: BasicStoreEntityIngestionRss, _, context: AuthContext) => findUserById(context, context.user, ingestionRss.user_id),
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
