import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixObject, StixOpenctiExtensionSDO } from '../../types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';

export const ENTITY_TYPE_DATA_SANITY_EXECUTION = 'DataSanityExecution';

export interface BasicStoreEntityDataSanity extends BasicStoreEntity {
  operation_name: string;
  last_run_date: Date;
  last_execution_time: number;
  last_run_success: boolean;
  last_run_message: string;
  last_run_output: string; // JSON-serialized SanityOperationRunOutput
  force_run: boolean;
  is_running: boolean;
}

export interface StoreEntityDataSanity extends StoreEntity {
  operation_name: string;
  last_run_date: Date;
  last_execution_time: number;
  last_run_success: boolean;
  last_run_message: string;
  last_run_output: string;
  force_run: boolean;
  is_running: boolean;
}

export interface StixDataSanity extends StixObject {
  operation_name: string;
  last_run_date: Date;
  last_execution_time: number;
  last_run_success: boolean;
  last_run_message: string;
  last_run_output: string;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO;
  };
}
