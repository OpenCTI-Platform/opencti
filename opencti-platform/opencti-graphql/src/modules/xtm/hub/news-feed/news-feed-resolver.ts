import type { QueryMyNewsFeedsArgs, Resolvers } from '../../../../generated/graphql';
import type { AuthContext } from '../../../../types/user';
import { myNewsFeedsFind, myUnreadNewsFeedsCount } from './news-feed-domain';

const newsFeedResolvers = {
  Query: {
    myNewsFeeds: (_: unknown, args: QueryMyNewsFeedsArgs, context: AuthContext) => myNewsFeedsFind(context, context.user!, args as any),
    myUnreadNewsFeedsCount: (_: unknown, __: unknown, context: AuthContext) => myUnreadNewsFeedsCount(context, context.user!),
  },
} as unknown as Resolvers;

export default newsFeedResolvers;
