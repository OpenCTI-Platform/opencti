import type { BasicStoreEntity, StoreEntity } from '../../../types/store';
import type { StixObject, StixOpenctiExtensionSDO } from '../../../types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../../types/stix-2-1-extensions';

export const ENTITY_TYPE_CASE_TEMPLATE = 'Case-Template';
export const TEMPLATE_TASK_RELATION = 'template-task';

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
