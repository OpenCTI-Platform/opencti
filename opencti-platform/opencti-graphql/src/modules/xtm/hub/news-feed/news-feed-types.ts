import type { BasicStoreEntity, StoreEntity } from '../../../../types/store';
import type { StixObject, StixOpenctiExtensionSDO } from '../../../../types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../../../types/stix-2-1-extensions';

export const ENTITY_TYPE_NEWS_FEED_ITEM = 'NewsFeedItem';

export enum NewsFeedItemType {
  RESOURCE_CUSTOM_DASHBOARD = 'RESOURCE_CUSTOM_DASHBOARD',
}

export interface NewsFeedItemMetadata {
  key: string;
  value: string | undefined;
}

export interface BasicStoreEntityNewsFeedItem extends BasicStoreEntity {
  title: string;
  news_feed_type: NewsFeedItemType;
  tags: string[];
  metadata: NewsFeedItemMetadata[];
  creation_date: Date;
  is_read: boolean;
  user_id: string;
}

export interface StoreEntityNewsFeedItem extends StoreEntity {
  title: string;
  news_feed_type: NewsFeedItemType;
  tags: string[];
  metadata: NewsFeedItemMetadata[];
  creation_date: Date;
  is_read: boolean;
  user_id: string;
}

export interface StixNewsFeedItem extends StixObject {
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
  title: string;
  news_feed_type: NewsFeedItemType;
  tags: string[];
  metadata: NewsFeedItemMetadata[];
  creation_date: Date;
  is_read?: boolean;
  user_id: string;
}
