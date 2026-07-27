import type { BasicStoreEntity, StoreEntity } from '../../../../types/store';
import type { StixObject, StixOpenctiExtensionSDO } from '../../../../types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../../../types/stix-2-1-extensions';

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

export interface StixNewsFeedItem extends StixObject {
  news_feed_item_id: string;
  title: string;
  news_feed_type: NewsFeedItemType;
  tags: string[];
  metadata: NewsFeedItemMetadata[];
  creation_date: Date;
  is_read: boolean;
  user_id: string;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO;
  };
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
