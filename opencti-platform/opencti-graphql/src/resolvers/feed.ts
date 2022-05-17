import { createFeed, feedDelete, findAll, editFeed, findById } from '../domain/feed';
import type { Resolvers } from '../generated/graphql';

const feedResolvers: Resolvers = {
  Query: {
    feed: (_, { id }, { user }) => findById(user, id),
    feeds: (_, args, { user }) => findAll(user, args),
  },
  Mutation: {
    feedAdd: (_, { input }, { user }) => createFeed(user, input),
    feedDelete: (_, { id }, { user }) => feedDelete(user, id),
    feedEdit: (_, { id, input }, { user }) => editFeed(user, id, input),
  },
};

export default feedResolvers;
