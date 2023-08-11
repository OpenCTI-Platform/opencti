import type { StixObject, StixOpenctiExtensionSDO } from '../../types/stix-common';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import type { StoreEntity, BasicStoreEntity } from '../../types/store';

export const ENTITY_TYPE_INGESTION = 'Ingestion';

export interface BasicStoreEntityIngestion extends BasicStoreEntity {
  name: string
  description: string
  uri: string
  user_id: string | undefined
  created_by_ref: string | undefined
  report_types: string[]
  object_marking_refs: string[] | undefined
  current_state_date: Date | undefined
  ingestion_running: boolean
}

export interface StoreEntityIngestion extends StoreEntity {
  name: string
  description: string
  uri: string
  report_types: string[]
  ingestion_running: boolean
}

export interface StixIngestion extends StixObject {
  name: string
  description: string
  uri: string
  report_types: string[]
  ingestion_running: boolean
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO
  }
}
