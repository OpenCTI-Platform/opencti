import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixObject, StixOpenctiExtensionSDO } from '../../types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';

export const ENTITY_TYPE_DATA_SANITY = 'DataSanity';

export interface BasicStoreEntityDataSanity extends BasicStoreEntity {
  fix_name: string;
  last_run_date: Date;
  last_execution_time: number;
  last_failure_message: string;
  force_run: boolean;
}

export interface StoreEntityDataSanity extends StoreEntity {
  fix_name: string;
  last_run_date: Date;
  last_execution_time: number;
  last_failure_message: string;
  force_run: boolean;
}

export interface StixDataSanity extends StixObject {
  fix_name: string;
  last_run_date: Date;
  last_execution_time: number;
  last_failure_message: string;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO;
  };
}
