import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import type { StixObject, StixOpenctiExtensionSDO } from '../../types/stix-common';
import type { FintelTemplateWidget } from '../../generated/graphql';

export const ENTITY_TYPE_FINTEL_TEMPLATE = 'FintelTemplate';

export interface FintelTemplate {
  name: string;
  description: string;
  settings_types: [string];
  instance_filters: string;
  content: string;
  fintel_template_widgets: [FintelTemplateWidget];
  start_date: string;
}

// region Database types
export interface BasicStoreEntityFintelTemplate extends BasicStoreEntity {
  name: string;
  description: string;
  settings_types: [string];
  instance_filters: string;
  content: string;
  fintel_template_widgets: [FintelTemplateWidget];
  start_date: string;
}

export interface StoreEntityFintelTemplate extends StoreEntity {
  name: string;
  description: string;
  settings_types: [string];
  instance_filters: string;
  content: string;
  fintel_template_widgets: [FintelTemplateWidget];
  start_date: string;
}
// endregion

// region Stix type
export interface StixFintelTemplate extends StixObject {
  name: string;
  description: string;
  settings_types: [string];
  instance_filters: string;
  content: string;
  fintel_template_widgets: [FintelTemplateWidget];
  start_date: string;
  extensions: {
    [STIX_EXT_OCTI] : StixOpenctiExtensionSDO
  };
}
// endregion
