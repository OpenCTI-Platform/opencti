import type { BasicStoreRelation, StoreRelation } from '../../types/store';
import { RELATION_DEPLOYED_ON } from '../../schema/stixCoreRelationship';

export { RELATION_DEPLOYED_ON };

// Lifecycle of an indicator on a security platform, written back by the stream connectors.
export const DEPLOYMENT_STATUS_PENDING = 'pending';
export const DEPLOYMENT_STATUS_DEPLOYED = 'deployed';
export const DEPLOYMENT_STATUS_ACTIVE = 'active';
export const DEPLOYMENT_STATUS_FAILED = 'failed';
export const DEPLOYMENT_STATUS_REMOVED = 'removed';
export const DEPLOYMENT_STATUS_EXPIRED = 'expired';
export const DEPLOYMENT_STATUSES = [
  DEPLOYMENT_STATUS_PENDING,
  DEPLOYMENT_STATUS_DEPLOYED,
  DEPLOYMENT_STATUS_ACTIVE,
  DEPLOYMENT_STATUS_FAILED,
  DEPLOYMENT_STATUS_REMOVED,
  DEPLOYMENT_STATUS_EXPIRED,
] as const;
export type DeploymentStatus = typeof DEPLOYMENT_STATUSES[number];
// Statuses meaning the indicator is currently live on the platform.
export const LIVE_DEPLOYMENT_STATUSES: DeploymentStatus[] = [DEPLOYMENT_STATUS_DEPLOYED, DEPLOYMENT_STATUS_ACTIVE];

// Outcome of the OpenAEV validation of a deployed indicator.
export const VALIDATION_STATUS_NOT_REQUESTED = 'not_requested';
export const VALIDATION_STATUS_REQUESTED = 'requested';
export const VALIDATION_STATUS_DETECTED = 'detected';
export const VALIDATION_STATUS_PREVENTED = 'prevented';
export const VALIDATION_STATUS_MISSED = 'missed';
export const VALIDATION_STATUS_ERROR = 'error';
export const VALIDATION_STATUSES = [
  VALIDATION_STATUS_NOT_REQUESTED,
  VALIDATION_STATUS_REQUESTED,
  VALIDATION_STATUS_DETECTED,
  VALIDATION_STATUS_PREVENTED,
  VALIDATION_STATUS_MISSED,
  VALIDATION_STATUS_ERROR,
] as const;
export type ValidationStatus = typeof VALIDATION_STATUSES[number];
// Statuses proving the security platform reacted to the indicator.
export const PROVEN_VALIDATION_STATUSES: ValidationStatus[] = [VALIDATION_STATUS_DETECTED, VALIDATION_STATUS_PREVENTED];

// Attributes carried by a deployed-on relationship (Indicator -> Security Platform).
export interface DeployedOnAttributes {
  deployment_status: DeploymentStatus;
  external_id?: string | null;
  deployed_at?: Date | string | null;
  last_sync_at?: Date | string | null;
  removed_at?: Date | string | null;
  removal_requested_at?: Date | string | null;
  hit_count: number;
  first_hit_at?: Date | string | null;
  last_hit_at?: Date | string | null;
  last_hit_report_ids?: string[] | null;
  validation_status: ValidationStatus;
  last_validation_at?: Date | string | null;
  validation_run_id?: string | null;
  error_message?: string | null;
}

export interface BasicStoreRelationDeployedOn extends BasicStoreRelation, DeployedOnAttributes {}
export interface StoreRelationDeployedOn extends StoreRelation, DeployedOnAttributes {}

// Derived, filterable counters maintained on the Indicator.
// deployments_count: platforms that recorded the indicator, whatever the status (dissemination evidence).
// deployment_platforms_count: live deployments only; deployment_expired_count: removals never confirmed.
export const INDICATOR_DEPLOYMENTS_COUNT = 'deployments_count';
export const INDICATOR_DEPLOYMENT_PLATFORMS_COUNT = 'deployment_platforms_count';
export const INDICATOR_DEPLOYMENT_FAILED_COUNT = 'deployment_failed_count';
export const INDICATOR_DEPLOYMENT_EXPIRED_COUNT = 'deployment_expired_count';
export const INDICATOR_VALIDATED_PLATFORMS_COUNT = 'validated_platforms_count';
export const INDICATOR_HIT_PLATFORMS_COUNT = 'hit_platforms_count';
export interface IndicatorDeploymentCounters {
  [INDICATOR_DEPLOYMENTS_COUNT]: number;
  [INDICATOR_DEPLOYMENT_PLATFORMS_COUNT]: number;
  [INDICATOR_DEPLOYMENT_FAILED_COUNT]: number;
  [INDICATOR_DEPLOYMENT_EXPIRED_COUNT]: number;
  [INDICATOR_VALIDATED_PLATFORMS_COUNT]: number;
  [INDICATOR_HIT_PLATFORMS_COUNT]: number;
}
