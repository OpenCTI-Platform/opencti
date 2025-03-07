import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixObject } from '../../types/stix-common';

export const ENTITY_TYPE_SAVED_FILTER = 'SavedFilter';

export interface BasicStoreEntitySavedFilter extends BasicStoreEntity {
  user: string
  name: string
  filter: string
  scope: string[]
}

export interface StoreEntitySavedFilter extends StoreEntity {
  user: string
  name: string
  filter: string
  scope: string[]
}

export interface StixSavedFilter extends StixObject {
  user: string
  name: string
  filter: string
  scope: string[]
}
