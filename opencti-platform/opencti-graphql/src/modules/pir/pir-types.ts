import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixInternal } from '../../types/stix-2-1-common';

export const ENTITY_TYPE_PIR = 'PIR';

export interface BasicStoreEntityPIR extends BasicStoreEntity {
  name: string
  pirCriteria: string
  pirFilters: string
}

export interface StoreEntityPIR extends StoreEntity {
  name: string
  pirCriteria: string
  pirFilters: string
}

export interface StixPIR extends StixInternal {
  name: string
}
