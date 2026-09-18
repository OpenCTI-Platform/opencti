import type { BasicStoreEntity, StoreEntity } from '../../types/store';

export const ENTITY_TYPE_RETENTION_RULE = 'RetentionRule';

export interface BasicStoreEntityRetentionRule extends BasicStoreEntity {
  name: string;
  filters: string;
  max_retention: number;
  retention_unit: string;
  scope: string;
  active: boolean;
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
  active: boolean;
  last_execution_date: string | null;
  last_deleted_count: number | null;
  remaining_count: number | null;
}
