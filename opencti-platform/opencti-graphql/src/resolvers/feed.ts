import { createFeed, feedDelete, findAll, editFeed, findById } from '../domain/feed';
import type { Resolvers } from '../generated/graphql';
import { getAuthorizedMembers } from '../utils/authorizedMembers';

const feedResolvers: Resolvers = {
  Query: {
    feed: (_, { id }, context) => findById(context, context.user, id),
    feeds: (_, args, context) => findAll(context, context.user, args),
  },
  Feed: {
    authorized_members: (feed, _, context) => getAuthorizedMembers(context, context.user, feed),
  },
  Mutation: {
    feedAdd: (_, { input }, context) => createFeed(context, context.user, input),
    feedDelete: (_, { id }, context) => feedDelete(context, context.user, id),
    feedEdit: (_, { id, input }, context) => editFeed(context, context.user, id, input),
  },
};

export default feedResolvers;
