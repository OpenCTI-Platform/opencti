import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixObject, StixOpenctiExtensionSDO } from '../../types/stix-common';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import type { FintelTemplate } from '../fintelTemplate/fintelTemplate-types';

export const ENTITY_TYPE_ENTITY_SETTING = 'EntitySetting';

export interface AttributeConfiguration {
  name: string
  mandatory: boolean
  default_values?: string[]
  scale?: Scale
}

export interface Scale {
  local_config: ScaleConfig;
}

export interface ScaleConfig {
  better_side: string;
  min: Tick;
  max: Tick;
  ticks: Array<Tick>
}

export interface Tick {
  value: number;
  color: string;
  label: string;
}

export interface BasicStoreEntityEntitySetting extends BasicStoreEntity {
  target_type: string;
  platform_entity_files_ref: boolean;
  platform_hidden_type: boolean;
  enforce_reference: boolean;
  attributes_configuration?: string;
  workflow_configuration: boolean;
  availableSettings?: string[];
  overview_layout_customization?: Array<OverviewLayoutCustomization>;
  templates?: Array<FintelTemplate>;
}

export interface OverviewLayoutCustomization {
  key: string;
  width: number;
  label: string;
}

export interface StoreEntityEntitySetting extends StoreEntity {
  target_type: string;
  platform_entity_files_ref: boolean;
  platform_hidden_type: boolean;
  enforce_reference: boolean;
  attributes_configuration?: string;
  workflow_configuration: boolean;
  availableSettings?: string[];
  overviewLayoutCustomization?: Array<string>;
  templates?: Array<FintelTemplate>;
}

export interface StixEntitySetting extends StixObject {
  target_type: string;
  platform_entity_files_ref: boolean;
  platform_hidden_type: boolean;
  enforce_reference: boolean;
  attributes_configuration?: string;
  workflow_configuration: boolean;
  available_settings?: string[];
  templates?: Array<FintelTemplate>;
  extensions: {
    [STIX_EXT_OCTI] : StixOpenctiExtensionSDO
  }
}
