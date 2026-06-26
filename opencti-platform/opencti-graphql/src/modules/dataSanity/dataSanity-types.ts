import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixObject, StixOpenctiExtensionSDO } from '../../types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import type { AuthContext } from '../../types/user';

export const ENTITY_TYPE_DATA_SANITY_EXECUTION = 'DataSanityExecution';

export interface BasicStoreEntityDataSanity extends BasicStoreEntity {
  operation_name: string;
  last_run_date: Date;
  last_execution_time: number;
  last_failure_message: string;
  force_run: boolean;
}

export interface StoreEntityDataSanity extends StoreEntity {
  operation_name: string;
  last_run_date: Date;
  last_execution_time: number;
  last_failure_message: string;
  force_run: boolean;
}

export interface StixDataSanity extends StixObject {
  operation_name: string;
  last_run_date: Date;
  last_execution_time: number;
  last_failure_message: string;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO;
  };
}

// run_once: executes only once, then never again unless requested by a force_run
// on_demand: executes only when force_run is set to true in the DataSanity entity
// periodic: executes on every manager run
export type ExecutionType = 'run_once' | 'on_demand' | 'periodic';
// Map of entity_type or relation_type to the number of impacted elements
export type ImpactedElementsMap = Record<string, number>;

export interface SanityOperationDryRunOutput {
  message: string;
  estimated_impact: ImpactedElementsMap; // estimated impacted elements per entity/relation type
}

export interface SanityOperationRunOutput {
  message: string;
  impact: ImpactedElementsMap; // actual impacted elements per entity/relation type
}

export interface SanityOperation {
  name: string; // unique name to identify the sanity operation
  execution_type: ExecutionType;
  dryRun: (context: AuthContext) => Promise<SanityOperationDryRunOutput>; // dry run: returns estimated impact without modifying data
  operationRun: (context: AuthContext) => Promise<SanityOperationRunOutput>; // actual run: applies the operation and returns impact
}
