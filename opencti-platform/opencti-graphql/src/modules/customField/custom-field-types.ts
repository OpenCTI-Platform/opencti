import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixObject, StixOpenctiExtensionSDO } from '../../types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';

export const ENTITY_TYPE_CUSTOM_FIELD_DEFINITION = 'CustomFieldDefinition';

// Prefix for custom field names stored on entities
export const CUSTOM_FIELD_PREFIX = 'x_opencti_cf_';

// Field types supported by custom fields
export type CustomFieldType = 'integer' | 'string' | 'boolean' | 'date' | 'select';

export interface CustomFieldValue {
  field_id: string;
  field_name: string;
  int_value?: number;
  string_value?: string;
  boolean_value?: boolean;
  date_value?: string;
  select_value?: string;
}

export interface BasicStoreEntityCustomFieldDefinition extends BasicStoreEntity {
  name: string;
  description: string;
  label: string;
  field_type: CustomFieldType;
  entity_types?: string[];
  mandatory: boolean;
  multiple: boolean;
  // Common optional
  default_value?: string;
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
  mandatory: boolean;
  multiple: boolean;
  default_value?: string;
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
  mandatory: boolean;
  multiple: boolean;
  default_value?: string;
  min_value?: number;
  max_value?: number;
  select_options?: string[];
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO;
  };
}
