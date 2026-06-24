import type { AuthContext, AuthUser } from '../../../../types/user';
import { ENTITY_TYPE_NEWS_FEED_ITEM, NEWS_FEED_NUMBER, type BasicStoreEntityNewsFeedItem, type StoreEntityNewsFeedItem } from './news-feed-types';
import type { NewsFeedAddInput } from './news-feed-types';
import { createInternalObject } from '../../../../domain/internalObject';
import { addFilter } from '../../../../utils/filtering/filtering-utils';
import { fullEntitiesList, pageEntitiesConnection } from '../../../../database/middleware-loader';
import { elCount, elPaginate } from '../../../../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../../../../database/utils';
import { FilterMode, FilterOperator, type QueryMyNewsFeedsArgs } from '../../../../generated/graphql';
import { notify } from '../../../../database/redis';
import { deleteElementById, patchAttribute } from '../../../../database/middleware';
import { BUS_TOPICS, logApp } from '../../../../config/conf';
import { ALREADY_DELETED_ERROR } from '../../../../config/errors';
import { promiseMap } from '../../../../utils/promiseUtils';

export const myUnreadNewsFeedsCount = (context: AuthContext, user: AuthUser, userId?: string | null) => {
  const queryFilters = {
    mode: FilterMode.And,
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

const NEWS_FEED_CLEANUP_BATCH_SIZE = 1500;
const NEWS_FEED_CLEANUP_CONCURRENCY = 5;

export const addNewsFeed = async (context: AuthContext, user: AuthUser, input: NewsFeedAddInput) => {
  const newsFeedToCreate = {
    news_feed_item_id: input.news_feed_item_id,
    title: input.title,
    news_feed_type: input.news_feed_type,
    metadata: input.metadata ?? [],
    creation_date: input.creation_date,
    user_id: input.user_id,
    is_read: input.is_read ?? false,
    tags: input.tags ?? [],
  };
  const created = await createInternalObject<StoreEntityNewsFeedItem>(context, user, newsFeedToCreate, ENTITY_TYPE_NEWS_FEED_ITEM);
  const unreadNewsFeedsCount = await myUnreadNewsFeedsCount(context, user, created.user_id);
  await notify(BUS_TOPICS[NEWS_FEED_NUMBER].EDIT_TOPIC, { count: unreadNewsFeedsCount, user_id: created.user_id }, user);
  return created;
};

const findNewsFeedByExternalId = async (context: AuthContext, user: AuthUser, userId: string, newsFeedItemId: string) => {
  const queryFilters = {
    mode: FilterMode.And,
    filters: [
      { key: ['user_id'], values: [userId] },
      { key: ['news_feed_item_id'], values: [newsFeedItemId] },
    ],
    filterGroups: [],
  };
  const existing = await fullEntitiesList<BasicStoreEntityNewsFeedItem>(context, user, [ENTITY_TYPE_NEWS_FEED_ITEM], { filters: queryFilters });
  return existing[0];
};

export const upsertNewsFeed = async (context: AuthContext, user: AuthUser, input: NewsFeedAddInput) => {
  const existing = await findNewsFeedByExternalId(context, user, input.user_id, input.news_feed_item_id);
  if (!existing) {
    return addNewsFeed(context, user, input);
  }

  const patch = {
    title: input.title,
    tags: input.tags ?? [],
    metadata: input.metadata ?? [],
    creation_date: input.creation_date,
    news_feed_type: input.news_feed_type,
  };
  const { element } = await patchAttribute<StoreEntityNewsFeedItem>(context, user, existing.id, ENTITY_TYPE_NEWS_FEED_ITEM, patch);
  await notify(BUS_TOPICS[ENTITY_TYPE_NEWS_FEED_ITEM].EDIT_TOPIC, element, user);
  return element;
};

export const deleteNewsFeedItemsByExternalId = async (context: AuthContext, user: AuthUser, newsFeedItemId: string): Promise<number> => {
  const queryFilters = {
    mode: FilterMode.And,
    filters: [{ key: ['news_feed_item_id'], values: [newsFeedItemId] }],
    filterGroups: [],
  };
  const toDelete = await fullEntitiesList<BasicStoreEntityNewsFeedItem>(context, user, [ENTITY_TYPE_NEWS_FEED_ITEM], { filters: queryFilters });
  const impactedUsers = new Set<string>();
  await promiseMap(toDelete, async (item) => {
    impactedUsers.add(item.user_id);
    await deleteElementById(context, user, item.id, ENTITY_TYPE_NEWS_FEED_ITEM);
    await notify(BUS_TOPICS[ENTITY_TYPE_NEWS_FEED_ITEM].DELETE_TOPIC, item, user);
  }, 5);

  await promiseMap(Array.from(impactedUsers), async (userId) => {
    const unreadNewsFeedsCount = await myUnreadNewsFeedsCount(context, user, userId);
    await notify(BUS_TOPICS[NEWS_FEED_NUMBER].EDIT_TOPIC, { count: unreadNewsFeedsCount, user_id: userId }, user);
  }, 5);

  return toDelete.length;
};

export const markAllNewsFeedItemsAsRead = async (context: AuthContext, user: AuthUser): Promise<boolean> => {
  const queryFilters = {
    mode: FilterMode.And,
    filters: [
      { key: ['user_id'], values: [user.id] },
      { key: ['is_read'], values: [false] },
    ],
    filterGroups: [],
  };
  const unreadItems = await fullEntitiesList<BasicStoreEntityNewsFeedItem>(context, user, [ENTITY_TYPE_NEWS_FEED_ITEM], { filters: queryFilters });
  await promiseMap(unreadItems, (item) => patchAttribute(context, user, item.id, ENTITY_TYPE_NEWS_FEED_ITEM, { is_read: true }), 5);
  const remainingUnreadCount = await myUnreadNewsFeedsCount(context, user);
  await notify(BUS_TOPICS[NEWS_FEED_NUMBER].EDIT_TOPIC, { count: remainingUnreadCount, user_id: user.id }, user);
  return true;
};

export const cleanOldNewsFeedItems = async (
  context: AuthContext,
  user: AuthUser,
  cutoffDate: Date,
): Promise<number> => {
  const filters = {
    mode: FilterMode.And,
    filters: [
      {
        key: ['creation_date'],
        values: [cutoffDate.toISOString()],
        operator: FilterOperator.Lt,
      },
    ],
    filterGroups: [],
  };

  let totalDeleted = 0;

  while (true) {
    const result = await elPaginate(context, user, READ_INDEX_INTERNAL_OBJECTS, {
      filters,
      types: [ENTITY_TYPE_NEWS_FEED_ITEM],
      first: NEWS_FEED_CLEANUP_BATCH_SIZE,
    }) as any;

    if (!result.edges || result.edges.length === 0) {
      break;
    }

    await promiseMap(
      result.edges,
      async (edge: any) => {
        try {
          await deleteElementById(
            context,
            user,
            edge.node.internal_id,
            ENTITY_TYPE_NEWS_FEED_ITEM,
          );
          totalDeleted += 1;
        } catch (err: any) {
          if (err?.extensions?.code !== ALREADY_DELETED_ERROR) {
            logApp.error('[XTMH] Failed to delete news feed item during cleanup', {
              cause: err,
              id: edge.node.internal_id,
            });
          }
        }
      },
      NEWS_FEED_CLEANUP_CONCURRENCY,
    );

    if (result.edges.length < NEWS_FEED_CLEANUP_BATCH_SIZE) {
      break;
    }
  }

  return totalDeleted;
};
