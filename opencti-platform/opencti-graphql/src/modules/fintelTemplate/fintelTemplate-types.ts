import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import type { StixObject, StixOpenctiExtensionSDO } from '../../types/stix-common';

export const ENTITY_TYPE_FINTEL_TEMPLATE = 'FintelTemplate';

export interface FintelTemplate {
  name: string;
  description: string;
  availableForTypes: string;
  filters: string;
  content: string;
  template_widgets_ids: [string];
  enabled: boolean;
}

// region Database types
export interface BasicStoreEntityFintelTemplate extends BasicStoreEntity {
  name: string;
  description: string;
  availableForTypes: string;
  filters: string;
  content: string;
  template_widgets_ids: [string];
  enabled: boolean;
}

export interface StoreEntityFintelTemplate extends StoreEntity {
  name: string;
  description: string;
  availableForTypes: string;
  filters: string;
  content: string;
  template_widgets_ids: [string];
  enabled: boolean;
}
// endregion

// region Stix type
export interface StixFintelTemplate extends StixObject {
  name: string;
  description: string;
  availableForTypes: string;
  filters: string;
  content: string;
  template_widgets_ids: [string];
  enabled: boolean;
  extensions: {
    [STIX_EXT_OCTI] : StixOpenctiExtensionSDO
  };
}
// endregion
