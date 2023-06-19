import type { StixObject, StixOpenctiExtensionSDO } from '../../../types/stix-common';
import { STIX_EXT_OCTI } from '../../../types/stix-extensions';
import type { BasicStoreEntity, StoreEntity } from '../../../types/store';

export const ENTITY_TYPE_TASK_TEMPLATE = 'Task-Template';

export interface BasicStoreEntityTaskTemplate extends BasicStoreEntity {
  name: string
  description: string
  object_refs: string[]
}

export interface StoreEntityTaskTemplate extends StoreEntity {
  name: string
  description: string
}

export interface StixTaskTemplate extends StixObject {
  name: string
  description: string
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO
  }
}
