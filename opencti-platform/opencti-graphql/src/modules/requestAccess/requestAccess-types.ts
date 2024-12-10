import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixObject } from '../../types/stix-common';

export const ENTITY_TYPE_REQUEST_ACCESS = 'RequestAccess';

export interface BasicStoreEntityRequestAccess extends BasicStoreEntity {
  name: string
}

export interface StoreEntityRequestAccess extends BasicStoreEntityRequestAccess, StoreEntity {
}

export interface StixRequestAccess extends StixObject {
  name: string
}
