import type { BasicStoreEntity, StoreEntity } from '../../../types/store';
import type { StixDomainObject, StixOpenctiExtensionSDO } from '../../../types/stix-common';
import { STIX_EXT_OCTI } from '../../../types/stix-extensions';

export const ENTITY_TYPE_CONTAINER_CASE_RFI = 'Case-Rfi';

export interface BasicStoreEntityCaseRfi extends BasicStoreEntity {
  name: string,
  description: string,
  content: string,
  content_mapping: string,
  information_types: string,
  severity: string,
  priority: string,
  object_refs: Array<string>,
}

export interface StoreEntityCaseRfi extends StoreEntity {
  name: string,
  type: string,
  description: string,
  content: string,
  content_mapping: string,
  object_refs: Array<string>,
  information_types: string,
  severity: string,
  priority: string,
}

export interface StixCaseRfi extends StixDomainObject {
  name: string,
  description: string,
  content: string,
  content_mapping: string,
  object_refs: Array<string>,
  information_types: string,
  severity: string,
  priority: string,
  extensions: {
    [STIX_EXT_OCTI] : StixOpenctiExtensionSDO
  }
}
