import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixDomainObject, StixOpenctiExtensionSDO } from '../../types/stix-common';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';

export const ENTITY_TYPE_EVENT = 'Event';

// region Database types
export interface BasicStoreEntityEvent extends BasicStoreEntity {
  name: string;
  description: string;
  category: 'meeting';
}

export interface StoreEntityEvent extends StoreEntity {
  name: string;
  description: string;
  category: 'meeting';
}
// endregion

// region Stix type
export interface StixEvent extends StixDomainObject {
  name: string;
  description: string;
  category: 'meeting';
  aliases: Array<string>;
  extensions: {
    [STIX_EXT_OCTI] : StixOpenctiExtensionSDO
  };
}
// endregion
