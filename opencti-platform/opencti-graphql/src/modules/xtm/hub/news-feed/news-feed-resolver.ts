import type { QueryMyNewsFeedsArgs, Resolvers } from '../../../../generated/graphql';
import type { AuthContext } from '../../../../types/user';
import { markAllNewsFeedItemsAsRead, myNewsFeedsFind, myUnreadNewsFeedsCount } from './news-feed-domain';
import { BUS_TOPICS } from '../../../../config/conf';
import { ENTITY_TYPE_NEWS_FEED_ITEM, NEWS_FEED_NUMBER } from './news-feed-types';
import { subscribeToUserEvents } from '../../../../graphql/subscriptionWrapper';

const newsFeedResolvers = {
  Query: {
    myNewsFeeds: (_: unknown, args: QueryMyNewsFeedsArgs, context: AuthContext) => myNewsFeedsFind(context, context.user!, args),
    myUnreadNewsFeedsCount: (_: unknown, __: unknown, context: AuthContext) => myUnreadNewsFeedsCount(context, context.user!),
  },
  Mutation: {
    markAllNewsFeedItemsAsRead: (_: unknown, __: unknown, context: AuthContext) => markAllNewsFeedItemsAsRead(context, context.user!),
  },
  Subscription: {
    newsFeedItem: {
      resolve: /* v8 ignore next */ (payload: any) => payload.instance,
      subscribe: /* v8 ignore next */ (_: unknown, __: unknown, context: AuthContext) => {
        const bus = BUS_TOPICS[ENTITY_TYPE_NEWS_FEED_ITEM];
        return subscribeToUserEvents(context, [bus.ADDED_TOPIC, bus.EDIT_TOPIC]);
      },
    },
    newsFeedItemDeleted: {
      resolve: /* v8 ignore next */ (payload: any) => payload.instance?.id,
      subscribe: /* v8 ignore next */ (_: unknown, __: unknown, context: AuthContext) => {
        const bus = BUS_TOPICS[ENTITY_TYPE_NEWS_FEED_ITEM];
        return subscribeToUserEvents(context, [bus.DELETE_TOPIC]);
      },
    },
    newsFeedsNumber: {
      resolve: /* v8 ignore next */ (payload: any) => payload.instance,
      subscribe: /* v8 ignore next */ (_: unknown, __: unknown, context: AuthContext) => {
        const bus = BUS_TOPICS[NEWS_FEED_NUMBER];
        return subscribeToUserEvents(context, [bus.EDIT_TOPIC]);
      },
    },
  },
} as unknown as Resolvers;

export default newsFeedResolvers;
