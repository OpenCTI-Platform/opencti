import type { StixObject } from '../../types/stix-common';
import type { BasicStoreEntity, StoreEntity } from '../../types/store';

export const ENTITY_TYPE_DRAFT_WORKSPACE = 'DraftWorkspace';

export interface BasicStoreEntityDraftWorkspace extends BasicStoreEntity {
  name: string
  draft_status: string
  validation_work_id: string
}

export interface StoreEntityDraftWorkspace extends BasicStoreEntityDraftWorkspace, StoreEntity {
}

export interface StixDraftWorkspace extends StixObject {
  name: string
  draft_status: string
}
