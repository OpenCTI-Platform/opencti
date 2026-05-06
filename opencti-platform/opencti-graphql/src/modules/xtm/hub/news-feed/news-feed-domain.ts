import type { AuthContext, AuthUser } from '../../../../types/user';
import { ENTITY_TYPE_NEWS_FEED_ITEM, NEWS_FEED_NUMBER, type BasicStoreEntityNewsFeedItem, type StoreEntityNewsFeedItem } from './news-feed-types';
import type { NewsFeedAddInput } from './news-feed-types';
import { createInternalObject } from '../../../../domain/internalObject';
import { addFilter } from '../../../../utils/filtering/filtering-utils';
import { pageEntitiesConnection } from '../../../../database/middleware-loader';
import { elCount } from '../../../../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../../../../database/utils';
import type { QueryMyNewsFeedsArgs } from '../../../../generated/graphql';
import { notify } from '../../../../database/redis';
import { BUS_TOPICS } from '../../../../config/conf';

export const myUnreadNewsFeedsCount = (context: AuthContext, user: AuthUser, userId?: string | null) => {
  const queryFilters = {
    mode: 'and',
    filters: [
      { key: 'user_id', values: [userId ?? user.id] },
      { key: 'is_read', values: [false] },
    ],
    filterGroups: [],
  };
  const queryArgs = { filters: queryFilters, types: [ENTITY_TYPE_NEWS_FEED_ITEM] };
  return elCount(context, user, READ_INDEX_INTERNAL_OBJECTS, queryArgs);
};

export const myNewsFeedsFind = (context: AuthContext, user: AuthUser, opts: QueryMyNewsFeedsArgs) => {
  const queryFilters = addFilter(opts.filters, 'user_id', user.id);
  const queryArgs = { ...opts, filters: queryFilters };
  return pageEntitiesConnection<BasicStoreEntityNewsFeedItem>(context, user, [ENTITY_TYPE_NEWS_FEED_ITEM], queryArgs);
};

export const addNewsFeed = async (context: AuthContext, user: AuthUser, input: NewsFeedAddInput) => {
  const newsFeedToCreate = {
    ...input,
    is_read: input.is_read ?? false,
    tags: input.tags ?? [],
  };
  const created = await createInternalObject<StoreEntityNewsFeedItem>(context, user, newsFeedToCreate, ENTITY_TYPE_NEWS_FEED_ITEM);
  const unreadNewsFeedsCount = await myUnreadNewsFeedsCount(context, user, created.user_id);
  await notify(BUS_TOPICS[NEWS_FEED_NUMBER].EDIT_TOPIC, { count: unreadNewsFeedsCount, user_id: created.user_id }, user);
  return created;
};
