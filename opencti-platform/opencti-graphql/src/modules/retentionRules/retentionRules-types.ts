import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixObject, StixOpenctiExtensionSDO } from '../../types/stix-2-1-common';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';

export const ENTITY_TYPE_RETENTION_RULE = 'RetentionRule';

export interface BasicStoreEntityRetentionRule extends BasicStoreEntity {
  name: string;
  filters: string;
  max_retention: number;
  retention_unit: string;
  scope: string;
  last_execution_date: string | null;
  last_deleted_count: number | null;
  remaining_count: number | null;
}

export interface StoreEntityRetentionRule extends StoreEntity {
  name: string;
  filters: string;
  max_retention: number;
  retention_unit: string;
  scope: string;
  last_execution_date: string | null;
  last_deleted_count: number | null;
  remaining_count: number | null;
}

export interface StixRetentionRule extends StixObject {
  name: string;
  filters: string;
  max_retention: number;
  retention_unit: string;
  scope: string;
  last_execution_date: string | null;
  last_deleted_count: number | null;
  remaining_count: number | null;
  extensions: {
    [STIX_EXT_OCTI]: StixOpenctiExtensionSDO;
  };
}
