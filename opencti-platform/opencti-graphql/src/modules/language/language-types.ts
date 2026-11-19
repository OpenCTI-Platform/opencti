import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixId, StixObject, StixOpenctiExtensionSDO } from '../../types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import type { StixDomainObject as StixDomainObject2 } from '../../types/stix-2-0-common';

export const ENTITY_TYPE_LANGUAGE = 'Language';

// region Database types
export interface BasicStoreEntityLanguage extends BasicStoreEntity {
  name: string;
}

export interface StoreEntityLanguage extends StoreEntity {
  name: string;
}
// endregion

// region Stix type
export interface StixLanguage extends StixObject {
  name: string;
  aliases: Array<string>;
  created_by_ref: StixId | undefined; // optional
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO;
  };
}
// endregion

// region Stix 2.0 type
export interface Stix2Language extends StixDomainObject2 {
  name: string;
  aliases: Array<string>;
}
// endregion
