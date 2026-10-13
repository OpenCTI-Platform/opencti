import type { IngestionHealthStatus } from '../../generated/graphql';

// A check as stored in Elasticsearch: kind, severity and message are derived from the code (see ingestionHealth-checks)
export interface StoredHealthCheck {
  health_check_code: string;
  health_check_metadata: Record<string, unknown>;
}

// Fields written by the ingestion health manager only
export interface IngestionHealthFields {
  health_status?: IngestionHealthStatus;
  health_status_since?: string | null; // last change of the health status, null until first evaluated
  health_checks?: StoredHealthCheck[];
}
