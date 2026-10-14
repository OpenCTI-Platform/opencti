import type { IngestionHealthStatus } from '../../generated/graphql';

// A check as stored in Elasticsearch: kind, severity and message are derived from the code (see ingestionHealth-checks)
export interface StoredHealthCheck {
  health_check_code: string;
  health_check_metadata?: Record<string, unknown>;
}

// Content of the nested ingestion_health object, written by the ingestion health manager only
export interface StoredIngestionHealth {
  status: IngestionHealthStatus;
  status_since: string; // last change of the health status
  health_checks?: StoredHealthCheck[];
}

// ingestion_health is absent until the manager first evaluates the ingestion, and removed (null in a patch) when no status can be computed anymore
export interface IngestionHealthFields {
  ingestion_health?: StoredIngestionHealth | null;
}
