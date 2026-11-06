import type { StixObject } from '../../types/stix-2-1-common';
import type { BasicStoreEntity, StoreEntity } from '../../types/store';

export const ENTITY_TYPE_INGESTION_DEDUPLICATION_RULE = 'IngestionDeduplicationRule';

export interface BasicStoreEntityIngestionDeduplicationRule extends BasicStoreEntity {
  user_id: string;
  target_type: string;
  excluded_fields: string[];
}

export interface StoreEntityIngestionDeduplicationRule extends StoreEntity {
  user_id: string;
  target_type: string;
  excluded_fields: string[];
}

export interface StixIngestionDeduplicationRule extends StixObject {
  user_id: string;
  target_type: string;
  excluded_fields: string[];
}
