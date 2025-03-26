import type { StixObject, StixOpenctiExtensionSDO } from '../../types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import type { BasicStoreEntity, StoreEntity } from '../../types/store';

export const ENTITY_TYPE_DELETE_OPERATION = 'DeleteOperation';

export interface DeletedElement {
  id: string
  source_index: string
}

export interface BasicStoreEntityDeleteOperation extends BasicStoreEntity {
  main_entity_type: string
  main_entity_id: string
  main_entity_name: string
  deleted_elements: Array<DeletedElement>
}

export interface StoreEntityDeleteOperation extends BasicStoreEntityDeleteOperation, StoreEntity {
}

export interface StixDeleteOperation extends StixObject {
  main_entity_type: string
  main_entity_id: string
  main_entity_name: string
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO
  }
}
