import type { StixDate, StixOpenctiExtensionSDO } from '../../types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import type { StixContainer } from '../../types/stix-2-1-sdo';
import type { BasicStoreEntity, StoreEntity } from '../../types/store';

export const ENTITY_TYPE_CONTAINER_TASK = 'Task';

export interface BasicStoreEntityTask extends BasicStoreEntity {
  name: string
  description: string
  due_date: string
}

export interface StoreEntityTask extends StoreEntity {
  name: string
  description: string
  due_date: string
}

export interface StixTask extends StixContainer {
  name: string
  description: string
  due_date: StixDate
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO
  }
}
