import type { StixObject, StixOpenctiExtensionSDO } from '../../types/stix-2-1-common';
import type { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import type { BasicStoreEntity, StoreEntity } from '../../types/store';

// region Database types
export interface BasicStoreEntityTheme extends BasicStoreEntity {
  name: string;
  manifest: string;
}

export interface StoreEntityTheme extends StoreEntity {
  name: string;
  manifest: string;
}
// endregion

// region Stix type
export interface StixTheme extends StixObject {
  name: string;
  manifest: string;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO
  };
}
// endregion
