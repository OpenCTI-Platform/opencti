import type { BasicStoreEntity, StoreEntity } from '../../types/store';

export const ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA = 'Administrative-Area';

// region Database types
export interface BasicStoreEntityAdministrativeArea extends BasicStoreEntity {
  name: string;
  description: string;
}

export interface StoreEntityAdministrativeArea extends StoreEntity {
  name: string;
  description: string;
}
// endregion
