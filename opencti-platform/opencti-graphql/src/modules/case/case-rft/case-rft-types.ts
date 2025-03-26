import type { BasicStoreEntity, StoreEntity } from '../../../types/store';
import type { StixDomainObject, StixOpenctiExtensionSDO } from '../../../types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../../types/stix-2-1-extensions';

export const ENTITY_TYPE_CONTAINER_CASE_RFT = 'Case-Rft';

export interface BasicStoreEntityCaseRft extends BasicStoreEntity {
  name: string,
  description: string,
  content: string,
  content_mapping: string,
  takedown_types: string,
  severity: string,
  priority: string,
  object_refs: Array<string>,
}

export interface StoreEntityCaseRft extends StoreEntity {
  name: string,
  type: string,
  description: string,
  content: string,
  content_mapping: string,
  object_refs: Array<string>,
  takedown_types: string,
  severity: string,
  priority: string,
}

export interface StixCaseRft extends StixDomainObject {
  name: string,
  description: string,
  content: string,
  content_mapping: string,
  object_refs: Array<string>,
  takedown_types: string,
  severity: string,
  priority: string,
  extensions: {
    [STIX_EXT_OCTI] : StixOpenctiExtensionSDO
  }
}
