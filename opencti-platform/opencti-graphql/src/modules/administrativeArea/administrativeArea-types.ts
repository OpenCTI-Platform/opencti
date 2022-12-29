import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixDomainObject, StixOpenctiExtensionSDO } from '../../types/stix-common';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';

export const ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA = 'Administrative-Area';

// region Database types
export interface BasicStoreEntityAdministrativeArea extends BasicStoreEntity {
  name: string;
  description: string;
}

export interface StoreEntityAdministrativeArea extends StoreEntity {
  name: string;
  description: string;
}
// endregion

// region Stix type
export interface StixAdministrativeArea extends StixDomainObject {
  name: string;
  description: string;
  aliases: Array<string>;
  extensions: {
    [STIX_EXT_OCTI] : StixOpenctiExtensionSDO
  };
}
