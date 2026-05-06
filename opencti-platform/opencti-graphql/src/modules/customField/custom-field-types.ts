import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixObject, StixOpenctiExtensionSDO } from '../../types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';

export const ENTITY_TYPE_CUSTOM_FIELD = 'CustomField';

export interface BasicStoreEntityCustomField extends BasicStoreEntity {
  name: string;
  description: string;
  label: string;
  field_type: string; // 'integer' for now
  entity_types?: string[]; // optional: not yet assigned to any entity
  mandatory: boolean;
  // Common optional
  default_value?: string; // serialized as string, parsed according to field_type
  // Integer-specific
  min_value?: number;
  max_value?: number;
}

export interface StoreEntityCustomField extends StoreEntity {
  name: string;
  description: string;
  label: string;
  field_type: string;
  entity_types?: string[]; // optional: not yet assigned to any entity
  mandatory: boolean;
  default_value?: string;
  min_value?: number;
  max_value?: number;
}

export interface StixCustomField extends StixObject {
  name: string;
  description: string;
  label: string;
  field_type: string;
  entity_types?: string[]; // optional: not yet assigned to any entity
  mandatory: boolean;
  default_value?: string;
  min_value?: number;
  max_value?: number;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO;
  };
}
