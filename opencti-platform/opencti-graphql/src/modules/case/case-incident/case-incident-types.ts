import type { BasicStoreEntity, StoreEntity } from '../../../types/store';
import type { StixDomainObject, StixOpenctiExtensionSDO } from '../../../types/stix-2-1-common';
import type { StixDomainObject as Stix2DomainObject } from '../../../types/stix-2-0-common';
import { STIX_EXT_OCTI } from '../../../types/stix-2-1-extensions';

export const ENTITY_TYPE_CONTAINER_CASE_INCIDENT = 'Case-Incident';

export interface BasicStoreEntityCaseIncident extends BasicStoreEntity {
  name: string,
  description: string,
  content: string,
  content_mapping: string,
  severity: string,
  priority: string,
  response_types: string,
  object_refs: Array<string>,
}

export interface StoreEntityCaseIncident extends StoreEntity {
  name: string,
  description: string,
  content: string,
  content_mapping: string,
  severity: string,
  priority: string,
  object_refs: Array<string>,
  response_types: string,
}

export interface StixCaseIncident extends StixDomainObject {
  name: string,
  description: string,
  content: string,
  content_mapping: string,
  severity: string,
  priority: string,
  object_refs: Array<string>,
  response_types: string,
  extensions: {
    [STIX_EXT_OCTI] : StixOpenctiExtensionSDO
  }
}

// STIX 2.0
export interface Stix2CaseIncident extends Stix2DomainObject {
  name: string,
  description: string,
  severity: string,
  priority: string,
  object_refs: Array<string>,
  response_types: string,
}

export interface StoreEntityCaseIncident2 extends StoreEntity {
  name: string,
  description: string,
  severity: string,
  priority: string,
  object_refs: Array<string>,
  response_types: string,
}
