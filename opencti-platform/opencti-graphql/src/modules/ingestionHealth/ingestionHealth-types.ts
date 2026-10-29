import { type IngestionHealthStatus } from '../../generated/graphql';
import { type HealthCheckCode } from './ingestionHealth-registry';
import type { AuthContext, AuthUser } from '../../types/user';

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

// region health checks

// Computed once at the beginning of each period of the ingestion health manager, shared by the evaluation of every ingestion.
// Known before the runtime data is read: whether a check is enabled depends on it only, which tells what to read.
export interface GlobalIngestionHealthContext {
  // Connectors pinging continuously
  pingingConnectorsIds: Set<string>;
  // ms a status must stay unchanged before it is notified, from the platform settings (default when absent)
  notificationDelay?: number;
  // Checks disabled in the platform settings: neither read nor evaluated
  disabledHealthChecks?: HealthCheckCode[];
}

// The user an ingestor runs as, as needed by the checks
export interface HealthCheckUser {
  // Platform internal user (system...): not a user account an admin manages
  internal: boolean;
  user_service_account: boolean;
  // Same rule as the platform authorization (bypass, parent capabilities)
  hasCapability: (capability: string) => boolean;
}

// What the evaluation looks at, besides the configuration of the ingestion: whether a check applies, whether it fails, the status.
// A new check needing a new fact adds a field here, not a parameter to every function.
export interface SourceIngestionHealthContext extends GlobalIngestionHealthContext {
  // The moment of the evaluation, taken right after the runtime data is read: what is stale is judged against it
  evaluatedAt: string;
  // Values read by the runtime checks enabled for this ingestion, by check code: whether they are still fresh is judged here, not when read
  runtimeData?: RuntimeData;
  // Resolved by the manager for each ingestion: absent when no user is set or it does not exist anymore
  user?: HealthCheckUser;
}

// What a getRuntimeData may read through the platform, besides Redis: as the user of the ingestion health manager
export interface RuntimeDataReadContext {
  context: AuthContext;
  user: AuthUser;
}

// What describes one occurrence of a failing check, stored with it in Elasticsearch (health_check_metadata) and given back to message().
// Keep it a state, not a measure: it is compared at each period, a value changing every time (a date, a counter) rewrites the ingestion every time.
export type HealthCheckMetadata = Record<string, unknown>;

// getFailure returns null when the check passes, else the metadata of each failure of the check: one failure per element.
// A check fails once in most cases (a single element), several for a check with several occurrences at once (one per error a connector reports).
// An empty list is a single failure with nothing to tell
export type HealthCheckFailures = HealthCheckMetadata[] | null;

// The ingestor evaluated: a connector, a feed or a sync
export interface HealthCheckIngestor {
  internal_id: string;
  entity_type: string;
  // The user of a connector
  connector_user_id?: string | null;
  // The user of a feed or a sync
  user_id?: string | null;
  // The outcome of the last execution of a feed or a sync, patched by the ingestion manager or the sync manager
  last_execution_status?: string | null;
  connector_type?: string | null;
}

// endregion
