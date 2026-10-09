import type { BasicStoreEntity, StoreEntity } from '../../types/store';

export const ENTITY_TYPE_EXCLUSION_LIST = 'ExclusionList';

export interface BasicStoreEntityExclusionList extends BasicStoreEntity {
  name: string;
  description: string;
  exclusion_list_entity_types: string[];
  file_id: string;
  enabled: boolean;
  exclusion_list_values_count: number;
  exclusion_list_file_size: number;
}

export interface StoreEntityExclusionList extends StoreEntity {
  name: string;
  description: string;
  exclusion_list_entity_types: string[];
  file_id: string;
  enabled: boolean;
  exclusion_list_values_count: number;
  exclusion_list_file_size: number;
}
