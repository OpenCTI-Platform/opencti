import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import type { StixObject, StixOpenctiExtensionSDO } from '../../types/stix-common';

export const ENTITY_TYPE_TEMPLATE = 'Template';

// region Database types
export interface BasicStoreEntityTemplate extends BasicStoreEntity {
  name: string;
  description: string;
  availableForType: string;
  filters: string;
  content: string;
  template_widget_ids: [string];
  finished: boolean;
}

export interface StoreEntityTemplate extends StoreEntity {
  name: string;
  description: string;
  availableForType: string;
  filters: string;
  content: string;
  template_widget_ids: [string];
  finished: boolean;
}
// endregion

// region Stix type
export interface StixTemplate extends StixObject {
  name: string;
  description: string;
  availableForType: string;
  filters: string;
  content: string;
  template_widget_ids: [string];
  finished: boolean;
  extensions: {
    [STIX_EXT_OCTI] : StixOpenctiExtensionSDO
  };
}
// endregion
