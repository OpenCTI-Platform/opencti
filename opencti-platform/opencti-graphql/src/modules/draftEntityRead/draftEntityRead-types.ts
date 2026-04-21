import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixObject } from '../../types/stix-2-1-common';

export const ENTITY_TYPE_DRAFT_ENTITY_READ = 'DraftEntityRead';

export interface BasicStoreEntityDraftEntityRead extends BasicStoreEntity {
  user_id: string;
  draft_id: string;
  entity_id: string;
  is_read: boolean;
}

export interface StoreEntityDraftEntityRead extends StoreEntity {
  user_id: string;
  draft_id: string;
  entity_id: string;
  is_read: boolean;
}

export interface StixDraftEntityRead extends StixObject {
  user_id: string;
  draft_id: string;
  entity_id: string;
  is_read: boolean;
}
