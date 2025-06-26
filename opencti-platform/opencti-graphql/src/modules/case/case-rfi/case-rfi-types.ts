import type { BasicStoreEntity, StoreEntity } from '../../../types/store';
import type { StixDomainObject, StixOpenctiExtensionSDO } from '../../../types/stix-2-1-common';
import type { StixDomainObject as Stix2DomainObject } from '../../../types/stix-2-0-common';
import { STIX_EXT_OCTI } from '../../../types/stix-2-1-extensions';

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
  x_opencti_request_access: string
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
  x_opencti_request_access: string
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

// STIX 2.0
export interface Stix2CaseRfi extends Stix2DomainObject {
  name: string,
  description: string,
  severity: string,
  priority: string,
  object_refs: Array<string>,
  information_types: string,
}

export interface StoreEntityCaseRfi2 extends StoreEntity {
  name: string,
  description: string,
  severity: string,
  priority: string,
  object_refs: Array<string>,
  information_types: string,
}
