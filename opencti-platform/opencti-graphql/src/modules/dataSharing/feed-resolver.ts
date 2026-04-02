import type { Resolvers } from '../../generated/graphql';
import { createFeed, feedDelete, findFeedPaginated, editFeed, findById } from './feed-domain';
import { getAuthorizedMembers } from '../../utils/authorizedMembers';
import { loadCreator } from '../../database/members';

const feedResolvers: Resolvers = {
  Query: {
    feed: (_, { id }, context) => findById(context, context.user, id),
    feeds: (_, args, context) => findFeedPaginated(context, context.user, args),
  },
  Feed: {
    authorized_members: (feed, _, context) => getAuthorizedMembers(context, context.user, feed),
    feed_public_user: (feed, _, context) => feed.feed_public_user_id ? loadCreator(context, context.user, feed.feed_public_user_id) : null,
  },
  Mutation: {
    feedAdd: (_, { input }, context) => createFeed(context, context.user, input),
    feedDelete: (_, { id }, context) => feedDelete(context, context.user, id),
    feedEdit: (_, { id, input }, context) => editFeed(context, context.user, id, input),
  },
};

export default feedResolvers;
