import type { BasicStoreEntity, StoreEntity } from '../../../types/store';
import type { StixDomainObject, StixOpenctiExtensionSDO } from '../../../types/stix-common';
import { STIX_EXT_OCTI } from '../../../types/stix-extensions';

export const ENTITY_TYPE_CONTAINER_CASE_INCIDENT = 'Case-Incident';

export interface BasicStoreEntityCaseIncident extends BasicStoreEntity {
  name: string,
  description: string,
  severity: string,
  priority: string,
  response_types: string,
  object_refs: Array<string>,
}

export interface StoreEntityCaseIncident extends StoreEntity {
  name: string,
  severity: string,
  priority: string,
  description: string,
  object_refs: Array<string>,
  response_types: string,
}

export interface StixCaseIncident extends StixDomainObject {
  name: string,
  description: string,
  severity: string,
  priority: string,
  object_refs: Array<string>,
  response_types: string,
  extensions: {
    [STIX_EXT_OCTI] : StixOpenctiExtensionSDO
  }
}
