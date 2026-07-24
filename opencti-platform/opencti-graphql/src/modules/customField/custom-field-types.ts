import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixObject, StixOpenctiExtensionSDO } from '../../types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';

export const ENTITY_TYPE_CUSTOM_FIELD_DEFINITION = 'CustomFieldDefinition';

// Prefix for custom field names stored on entities
export const CUSTOM_FIELD_PREFIX = 'x_opencti_cf_';

// Field types supported by custom fields
// `markdown` reuses the string value channel; `multi_select` reuses select_options but stores an array (select_values).
export type CustomFieldType = 'integer' | 'string' | 'markdown' | 'boolean' | 'date' | 'select' | 'multi_select';

export interface CustomFieldValue {
  field_id: string;
  field_name: string;
  int_value?: number;
  string_value?: string;
  boolean_value?: boolean;
  date_value?: string;
  select_value?: string;
  select_values?: string[];
}

// Per-entity-type settings of a custom field definition.
// `mandatory` and `default_value` are defined for each entity type the field is
// attached to (US.2), not globally on the definition. Field-intrinsic constraints
// (field_type, min/max, select_options) stay global on the definition.
export interface CustomFieldEntityTypeSetting {
  entity_type: string;
  mandatory: boolean;
  default_value?: string;
}

// Per-entity-type settings of a custom field definition.
// `mandatory` and `default_value` are defined for each entity type the field is
// attached to (US.2), not globally on the definition. Field-intrinsic constraints
// (field_type, min/max, select_options) stay global on the definition.
export interface CustomFieldEntityTypeSetting {
  entity_type: string;
  mandatory: boolean;
  default_value?: string;
}

// Per-entity-type settings of a custom field definition.
// `mandatory` and `default_value` are defined for each entity type the field is
// attached to (US.2), not globally on the definition. Field-intrinsic constraints
// (field_type, min/max, select_options) stay global on the definition.
export interface CustomFieldEntityTypeSetting {
  entity_type: string;
  mandatory: boolean;
  default_value?: string;
}

export interface BasicStoreEntityCustomFieldDefinition extends BasicStoreEntity {
  name: string;
  description: string;
  label: string;
  field_type: CustomFieldType;
  entity_types?: string[];
  // Per-entity-type mandatory / default_value settings
  entity_type_settings?: CustomFieldEntityTypeSetting[];
  multiple: boolean;
  // Integer-specific
  min_value?: number;
  max_value?: number;
  // Select-specific
  select_options?: string[];
}

export interface StoreEntityCustomFieldDefinition extends StoreEntity {
  name: string;
  description: string;
  label: string;
  field_type: CustomFieldType;
  entity_types?: string[];
  entity_type_settings?: CustomFieldEntityTypeSetting[];
  multiple: boolean;
  min_value?: number;
  max_value?: number;
  select_options?: string[];
}

export interface StixCustomFieldDefinition extends StixObject {
  name: string;
  description: string;
  label: string;
  field_type: CustomFieldType;
  entity_types?: string[];
  entity_type_settings?: CustomFieldEntityTypeSetting[];
  multiple: boolean;
  min_value?: number;
  max_value?: number;
  select_options?: string[];
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO;
  };
}
