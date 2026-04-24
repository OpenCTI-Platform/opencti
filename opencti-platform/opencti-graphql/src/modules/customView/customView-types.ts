import type { StixObject, StixOpenctiExtensionSDO } from '../../types/stix-2-1-common';
import type { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import type { BasicStoreEntity, StoreEntity } from '../../types/store';

export const ENTITY_TYPE_CUSTOM_VIEW = 'CustomView';

// region Database types
export interface BasicStoreEntityCustomView extends BasicStoreEntity {
  name: string;
  description: string;
  slug: string;
  manifest: string;
  target_entity_type: string;
}

export interface StoreEntityCustomView extends StoreEntity {
  name: string;
  description: string;
  slug: string;
  manifest: string;
  target_entity_type: string;
}
// endregion

// region Stix type
export interface StixCustomView extends StixObject {
  name: string;
  description: string;
  slug: string;
  manifest: string;
  target_entity_type: string;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO;
  };
}
// endregion
