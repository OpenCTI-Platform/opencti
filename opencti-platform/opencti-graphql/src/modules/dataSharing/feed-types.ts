import type { BasicStoreEntityFeed, StoreEntity } from '../../types/store';

export const ENTITY_TYPE_FEED = 'Feed';

export type { BasicStoreEntityFeed };

export interface FeedAttributeMapping {
  type: string;
  attribute: string;
  relationship_type?: string;
  target_entity_type?: string;
}

export interface FeedAttributeDefinition {
  attribute: string;
  multi_match_strategy?: string;
  multi_match_separator?: string;
  mappings: FeedAttributeMapping[];
}

export interface StoreEntityFeed extends StoreEntity {
  name: string;
  description: string;
  filters: string;
  separator: string;
  rolling_time: number;
  include_header: boolean;
  feed_public: boolean;
  feed_public_user_id?: string | null;
  feed_types: string[];
  feed_date_attribute: string;
  feed_attributes: FeedAttributeDefinition[];
}
