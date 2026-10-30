import type { IngestionHealthStatus } from '../../generated/graphql';
import type { HealthCheckCode } from './ingestionHealth-registry';

// A check as stored in Elasticsearch: kind, severity and message are derived from the code (see ingestionHealth-checks).
export interface StoredHealthCheck {
  // string, not HealthCheckCode: a code written by another platform version can be unknown to this one
  health_check_code: string;
  health_check_metadata?: Record<string, unknown>;
}

// Scope of the activity event published when the status changes
export const HealthTransition = {
  Critical: 'critical',
  Degraded: 'degraded',
  Recovered: 'recovered',
} as const;
export type HealthTransition = typeof HealthTransition[keyof typeof HealthTransition];

// Content of the nested ingestion_health object, written by the ingestion health manager only
export interface StoredIngestionHealth {
  status: IngestionHealthStatus;
  status_since: string; // last change of the health status
  // Date of the health event published last, whatever its transition, and the status it reported:
  // an event is due only when the stable status differs from it, see computeHealthTransition. Both absent until the first event
  last_event_date?: string;
  last_event_status?: IngestionHealthStatus;
  health_checks?: StoredHealthCheck[];
}

// Content of the ingestion_health_settings object of the platform settings, edited from the Parameters page
export interface IngestionHealthSettings {
  // ms a status must stay unchanged before it is notified
  notification_delay?: number;
  // Checks never evaluated on the platform: a check absent from the list is enabled, so is a check added later
  disabled_health_checks?: HealthCheckCode[];
}

// ingestion_health is absent until the manager first evaluates the ingestion, and removed (null in a patch) when it is stopped
export interface IngestionHealthFields {
  ingestion_health?: StoredIngestionHealth | null;
}
