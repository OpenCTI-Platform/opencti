import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixObject, StixOpenctiExtensionSDO } from '../../types/stix-common';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';

export const ENTITY_TYPE_ENTITY_SETTING = 'EntitySetting';

export interface AttributeConfiguration {
  name: string;
  mandatory: boolean;
}

export interface BasicStoreEntityEntitySetting extends BasicStoreEntity {
  target_type: string;
  platform_entity_files_ref: boolean;
  platform_hidden_type: boolean;
  enforce_reference: boolean;
  attributes_configuration?: string;
}

export interface StoreEntityEntitySetting extends StoreEntity {
  target_type: string;
  platform_entity_files_ref: boolean;
  platform_hidden_type: boolean;
  enforce_reference: boolean;
  attributes_configuration?: string;
}

export interface StixEntitySetting extends StixObject {
  target_type: string;
  platform_entity_files_ref: boolean;
  platform_hidden_type: boolean;
  enforce_reference: boolean;
  attributes_configuration?: string;
  extensions: {
    [STIX_EXT_OCTI] : StixOpenctiExtensionSDO
  }
}
