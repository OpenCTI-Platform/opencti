import type { IngestionHealthStatus } from '../../generated/graphql';

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
  // Date of the failure event (critical or degraded) published last, removed once its recovery is published:
  // a recovery is due only while it is set, see computeHealthTransition
  last_event_date?: string;
  health_checks?: StoredHealthCheck[];
}

// ingestion_health is absent until the manager first evaluates the ingestion with a status, and removed (null in a patch) when it is stopped
export interface IngestionHealthFields {
  ingestion_health?: StoredIngestionHealth | null;
}
