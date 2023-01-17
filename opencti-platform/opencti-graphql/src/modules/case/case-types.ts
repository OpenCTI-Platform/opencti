import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixDomainObject, StixOpenctiExtensionSDO } from '../../types/stix-common';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';

export const ENTITY_TYPE_CONTAINER_CASE = 'Case';

export interface BasicStoreEntityCase extends BasicStoreEntity {
  name: string,
  description: string,
  context: string,
  object_refs: Array<string>,
}

export interface StoreEntityCase extends StoreEntity {
  name: string,
  type: string,
  severity: string,
  priority: string,
  rating: number,
  description: string,
  object_refs: Array<string>,
}

export interface StixCase extends StixDomainObject {
  name: string,
  description: string,
  case_type: string,
  severity: string,
  priority: string,
  rating: number,
  confidence: number,
  object_refs: Array<string>,
  extensions: {
    [STIX_EXT_OCTI] : StixOpenctiExtensionSDO
  }
}
