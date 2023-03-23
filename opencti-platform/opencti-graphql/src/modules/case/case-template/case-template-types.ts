import type { BasicStoreEntity, StoreEntity } from '../../../types/store';
import type { StixObject, StixOpenctiExtensionSDO } from '../../../types/stix-common';
import { STIX_EXT_OCTI } from '../../../types/stix-extensions';

export const ENTITY_TYPE_CASE_TEMPLATE = 'Case-Template';

export interface BasicStoreEntityCaseTemplate extends BasicStoreEntity {
  name: string
  description: string
  tasks: string[]
}

export interface StoreEntityCaseTemplate extends StoreEntity {
  name: string
  description: string
  tasks: string[]
}

export interface StixCaseTemplate extends StixObject {
  name: string
  description: string
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO
  }
}
