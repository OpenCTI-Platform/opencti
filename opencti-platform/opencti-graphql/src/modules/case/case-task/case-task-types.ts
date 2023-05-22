import type { StixOpenctiExtensionSDO } from '../../../types/stix-common';
import { STIX_EXT_OCTI } from '../../../types/stix-extensions';
import type { StixContainer } from '../../../types/stix-sdo';
import type { BasicStoreEntity, StoreEntity } from '../../../types/store';

export const ENTITY_TYPE_CONTAINER_CASE_TASK = 'Case-Task';

export interface BasicStoreEntityCaseTask extends BasicStoreEntity {
  name: string
  description: string
  dueDate: string
  useAsTemplate: boolean
  object_refs: string[]
}

export interface StoreEntityCaseTask extends StoreEntity {
  name: string
  description: string
  dueDate: string
  useAsTemplate: boolean
  object_refs: string[]
}

export interface StixCaseTask extends StixContainer {
  name: string
  description: string
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO
  }
}
