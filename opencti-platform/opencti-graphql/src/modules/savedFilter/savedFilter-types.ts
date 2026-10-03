import type { BasicStoreEntity, StoreEntity } from '../../types/store';

export const ENTITY_TYPE_SAVED_FILTER = 'SavedFilter';

export interface BasicStoreEntitySavedFilter extends BasicStoreEntity {
  name: string;
  filters: string;
  scope: string;
}

export interface StoreEntitySavedFilter extends StoreEntity {
  name: string;
  filters: string;
  scope: string;
}
