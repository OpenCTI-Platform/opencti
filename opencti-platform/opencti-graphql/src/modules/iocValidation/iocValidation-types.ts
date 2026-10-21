import type { BasicStoreEntity, StoreEntity } from '../../types/store';
import type { StixObject } from '../../types/stix-2-1-common';
import type { StixId } from '../../types/stix-2-1-common';

export const ENTITY_TYPE_IOC_VALIDATION_REQUEST = 'Ioc-Validation-Request';
// Scope declared by the OpenAEV connector receiving the validation requests.
export const IOC_VALIDATION_CONNECTOR_SCOPE = 'ioc-validation-request';
// Custom STIX object carrying the request in the bundle sent to OpenAEV.
export const STIX_IOC_VALIDATION_REQUEST_TYPE = 'x-opencti-ioc-validation-request';

// Limits keep a request small enough for one OpenAEV scenario and one approval.
export const IOC_VALIDATION_MAX_INDICATORS = 200;
export const IOC_VALIDATION_MAX_PLATFORMS = 10;

export const TEST_KIND_DNS_RESOLUTION = 'dns_resolution';
export const TEST_KIND_NETWORK_TRAFFIC = 'network_traffic';
export const TEST_KIND_HTTP_HEAD = 'http_head';
export const TEST_KIND_FILE_DROP = 'file_drop';
export const TEST_KIND_LOG_INJECTION = 'log_injection';
export const IOC_VALIDATION_TEST_KINDS = [
  TEST_KIND_DNS_RESOLUTION,
  TEST_KIND_NETWORK_TRAFFIC,
  TEST_KIND_HTTP_HEAD,
  TEST_KIND_FILE_DROP,
  TEST_KIND_LOG_INJECTION,
] as const;
export type IocValidationTestKind = typeof IOC_VALIDATION_TEST_KINDS[number];
// Default allow-list: DNS resolution only, never contacts adversary infrastructure directly.
export const DEFAULT_IOC_VALIDATION_TEST_KINDS: IocValidationTestKind[] = [TEST_KIND_DNS_RESOLUTION];

export const REQUEST_STATUS_PENDING = 'pending';
export const REQUEST_STATUS_SENT = 'sent';
export const REQUEST_STATUS_AWAITING_APPROVAL = 'awaiting_approval';
export const REQUEST_STATUS_RUNNING = 'running';
export const REQUEST_STATUS_COMPLETED = 'completed';
export const REQUEST_STATUS_PARTIAL = 'partial';
export const REQUEST_STATUS_FAILED = 'failed';
export const REQUEST_STATUS_REJECTED = 'rejected';
export const REQUEST_STATUS_EXPIRED = 'expired';
export const IOC_VALIDATION_REQUEST_STATUSES = [
  REQUEST_STATUS_PENDING,
  REQUEST_STATUS_SENT,
  REQUEST_STATUS_AWAITING_APPROVAL,
  REQUEST_STATUS_RUNNING,
  REQUEST_STATUS_COMPLETED,
  REQUEST_STATUS_PARTIAL,
  REQUEST_STATUS_FAILED,
  REQUEST_STATUS_REJECTED,
  REQUEST_STATUS_EXPIRED,
] as const;
export type IocValidationRequestStatus = typeof IOC_VALIDATION_REQUEST_STATUSES[number];
export const OPEN_REQUEST_STATUSES: IocValidationRequestStatus[] = [
  REQUEST_STATUS_PENDING,
  REQUEST_STATUS_SENT,
  REQUEST_STATUS_AWAITING_APPROVAL,
  REQUEST_STATUS_RUNNING,
];
export const FINAL_REQUEST_STATUSES: IocValidationRequestStatus[] = [
  REQUEST_STATUS_COMPLETED,
  REQUEST_STATUS_PARTIAL,
  REQUEST_STATUS_FAILED,
  REQUEST_STATUS_REJECTED,
  REQUEST_STATUS_EXPIRED,
];
// Statuses OpenAEV may report through iocValidationRequestStatusUpdate.
export const OPENAEV_REPORTABLE_STATUSES: IocValidationRequestStatus[] = [
  REQUEST_STATUS_AWAITING_APPROVAL,
  REQUEST_STATUS_RUNNING,
  REQUEST_STATUS_COMPLETED,
  REQUEST_STATUS_PARTIAL,
  REQUEST_STATUS_FAILED,
  REQUEST_STATUS_REJECTED,
];

export interface IocValidationIoc {
  indicator_id: string;
  indicator_ref: StixId;
  observable_type: string;
  value: string;
  test_kind: IocValidationTestKind;
  file_name?: string | null;
  hashes?: Record<string, string> | null;
}

export interface IocValidationPair {
  indicator_id: string;
  platform_id: string;
  deployed_on_id: string;
  // Outcome of the pair for this request, kept when a newer request takes the deployment over
  validation_status?: string;
  // The error outcome was set by the request timeout, not reported: a late verdict of this request may replace it
  timed_out?: boolean;
}

export interface IocValidationSkipped {
  indicator_id: string;
  platform_id?: string | null;
  reason: string;
}

export interface IocValidationResultsSummary {
  total: number;
  requested: number;
  detected: number;
  prevented: number;
  missed: number;
  error: number;
  skipped: number;
}

interface IocValidationRequestAttributes {
  name: string;
  platform_ids: string[];
  indicator_ids: string[];
  test_kinds: IocValidationTestKind[];
  status: IocValidationRequestStatus;
  status_message?: string | null;
  openaev_scenario_id?: string | null;
  openaev_simulation_id?: string | null;
  external_uri?: string | null;
  connector_id?: string | null;
  work_id?: string | null;
  results_summary: IocValidationResultsSummary;
  iocs: IocValidationIoc[];
  pairs: IocValidationPair[];
  skipped: IocValidationSkipped[];
  dispatched_at?: Date | string | null;
  completed_at?: Date | string | null;
}

export interface BasicStoreEntityIocValidationRequest extends BasicStoreEntity, IocValidationRequestAttributes {}

export interface StoreEntityIocValidationRequest extends StoreEntity, IocValidationRequestAttributes {}

export interface StixIocValidationRequest extends StixObject {
  name: string;
  status: string;
  test_kinds: string[];
}
