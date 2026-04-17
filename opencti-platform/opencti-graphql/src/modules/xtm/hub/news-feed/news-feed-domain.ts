import type { AuthContext, AuthUser } from '../../../../types/user';
import { ENTITY_TYPE_NEWS_FEED_ITEM, type StoreEntityNewsFeedItem } from './news-feed-types';
import type { NewsFeedAddInput } from './news-feed-types';
import { createInternalObject } from '../../../../domain/internalObject';

export const addNewsFeed = async (context: AuthContext, user: AuthUser, input: NewsFeedAddInput) => {
  const newsFeedToCreate = {
    ...input,
    is_read: input.is_read ?? false,
    tags: input.tags ?? [],
  };

  return createInternalObject<StoreEntityNewsFeedItem>(context, user, newsFeedToCreate, ENTITY_TYPE_NEWS_FEED_ITEM);
};
