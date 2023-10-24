import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixObject, StixOpenctiExtensionSDO } from '../../types/stix-common';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';

export const ENTITY_TYPE_MANAGER_CONFIGURATION = 'ManagerConfiguration';

export interface BasicStoreEntityManagerConfiguration extends BasicStoreEntity {
  manager_id: string;
  manager_running: boolean;
  last_run_start_date: Date;
  last_run_end_date: Date;
}

export interface StoreEntityManagerConfiguration extends StoreEntity {
  manager_id: string;
  manager_running: boolean;
  last_run_start_date: Date;
  last_run_end_date: Date;
}

export interface StixManagerConfiguration extends StixObject {
  manager_id: string;
  manager_running: boolean;
  last_run_start_date: Date;
  last_run_end_date: Date;
  extensions: {
    [STIX_EXT_OCTI] : StixOpenctiExtensionSDO
  }
}
