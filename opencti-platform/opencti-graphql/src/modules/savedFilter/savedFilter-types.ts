import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixObject } from '../../types/stix-common';

export const ENTITY_TYPE_SAVED_FILTER = 'SavedFilter';

export interface BasicStoreEntitySavedFilter extends BasicStoreEntity {
  name: string
  filters: string
  scope: string
}

export interface StoreEntitySavedFilter extends StoreEntity {
  name: string
  filters: string
  scope: string
}

export interface StixSavedFilter extends StixObject {
  name: string
  filters: string
  scope: string
}
