import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixObject, StixOpenctiExtensionSDO } from '../../types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';

export const ENTITY_TYPE_MANAGER_CONFIGURATION = 'ManagerConfiguration';

export interface BasicStoreEntityManagerConfiguration extends BasicStoreEntity {
  manager_id: string;
  manager_running: boolean;
  last_run_start_date: Date;
  last_run_end_date: Date;
  manager_setting: any;
}

export interface StoreEntityManagerConfiguration extends StoreEntity {
  manager_id: string;
  manager_running: boolean;
  last_run_start_date: Date;
  last_run_end_date: Date;
  manager_setting: any;
}

export interface StixManagerConfiguration extends StixObject {
  manager_id: string;
  manager_running: boolean;
  last_run_start_date: Date;
  last_run_end_date: Date;
  manager_setting: any;
  extensions: {
    [STIX_EXT_OCTI] : StixOpenctiExtensionSDO
  }
}
