import type { BasicStoreEntity, StoreEntity } from '../../../types/store';
import type { StixDomainObject, StixOpenctiExtensionSDO } from '../../../types/stix-2-1-common';
import type { StixContainer as Stix2Container } from '../../../types/stix-2-0-sdo';
import { STIX_EXT_OCTI } from '../../../types/stix-2-1-extensions';

export const ENTITY_TYPE_CONTAINER_FEEDBACK = 'Feedback';

export interface BasicStoreEntityFeedback extends BasicStoreEntity {
  name: string,
  description: string,
  content: string,
  content_mapping: string,
  rating: number,
  object_refs: Array<string>,
}

// STIX 2.1
export interface StoreEntityFeedback extends StoreEntity {
  name: string,
  description: string,
  content: string,
  content_mapping: string,
  rating: number,
  object_refs: Array<string>,
}

export interface StixFeedback extends StixDomainObject {
  name: string,
  description: string,
  content: string,
  content_mapping: string,
  rating: number,
  object_refs: Array<string>,
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO
  }
}

// STIX 2.0
export interface Stix2Feedback extends Stix2Container {
  name: string,
  description: string,
  rating: number,
}

export interface StoreEntityStix2Feedback extends StoreEntity {
  name: string,
  description: string,
  rating: number,
  object_refs: Array<string>,
}
