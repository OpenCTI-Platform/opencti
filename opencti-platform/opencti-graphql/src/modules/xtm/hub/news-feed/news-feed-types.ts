import type { BasicStoreEntity, StoreEntity } from '../../../../types/store';

export const ENTITY_TYPE_NEWS_FEED_ITEM = 'NewsFeedItem';
export const NEWS_FEED_NUMBER = 'NewsFeedNumber';

export enum NewsFeedItemType {
  RESOURCE_CUSTOM_DASHBOARD = 'RESOURCE_CUSTOM_DASHBOARD',
  RESOURCE_PLAYBOOK = 'RESOURCE_PLAYBOOK',
  RESOURCE_CUSTOM_VIEW = 'RESOURCE_CUSTOM_VIEW',
}

export interface NewsFeedItemMetadata {
  key: string;
  value: string | undefined;
}

export interface BasicStoreEntityNewsFeedItem extends BasicStoreEntity {
  news_feed_item_id: string;
  title: string;
  news_feed_type: NewsFeedItemType;
  tags: string[];
  metadata: NewsFeedItemMetadata[];
  creation_date: Date;
  is_read: boolean;
  user_id: string;
}

export interface StoreEntityNewsFeedItem extends StoreEntity {
  news_feed_item_id: string;
  title: string;
  news_feed_type: NewsFeedItemType;
  tags: string[];
  metadata: NewsFeedItemMetadata[];
  creation_date: Date;
  is_read: boolean;
  user_id: string;
}

export interface NewsFeedAddInput {
  news_feed_item_id: string;
  title: string;
  news_feed_type: NewsFeedItemType;
  tags: string[];
  metadata: NewsFeedItemMetadata[];
  creation_date: Date;
  is_read?: boolean;
  user_id: string;
}
