import type { BasicStoreEntity, StoreEntity } from '../../../types/store';
import type { StixDomainObject, StixOpenctiExtensionSDO } from '../../../types/stix-common';
import { STIX_EXT_OCTI } from '../../../types/stix-extensions';

export const ENTITY_TYPE_CONTAINER_FEEDBACK = 'Feedback';

export interface BasicStoreEntityFeedback extends BasicStoreEntity {
  name: string,
  description: string,
  rating: number,
  object_refs: Array<string>,
}

export interface StoreEntityFeedback extends StoreEntity {
  name: string,
  rating: number,
  description: string,
  object_refs: Array<string>,
}

export interface StixFeedback extends StixDomainObject {
  name: string,
  description: string,
  rating: number,
  object_refs: Array<string>,
  extensions: {
    [STIX_EXT_OCTI] : StixOpenctiExtensionSDO
  }
}
