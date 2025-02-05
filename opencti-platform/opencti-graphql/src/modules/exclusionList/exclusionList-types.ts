import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixObject, StixOpenctiExtensionSDO } from '../../types/stix-common';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';

export const ENTITY_TYPE_EXCLUSION_LIST = 'ExclusionList';

export interface BasicStoreEntityExclusionList extends BasicStoreEntity {
  name: string
  description: string
  exclusion_list_entity_types: string[]
  file_id: string
  enabled: boolean
  exclusion_list_values_count: number
  exclusion_list_file_size: number
}

export interface StoreEntityExclusionList extends StoreEntity {
  name: string
  description: string
  exclusion_list_entity_types: string[]
  file_id: string
  enabled: boolean
  exclusion_list_values_count: number
  exclusion_list_file_size: number
}

export interface StixExclusionList extends StixObject {
  name: string
  description: string
  exclusion_list_entity_types: string[]
  file_id: string
  enabled: boolean
  extensions: {
    [STIX_EXT_OCTI] : StixOpenctiExtensionSDO
  }
}
