// Ingestion health evaluator types (RFC 0001). No platform import here:
// the evaluator is a pure function, called by the manager only.

// The six runtime states of RFC 0001 §4.1. Chunk 1 only produces unknown, critical and stopped,
// the full set is exposed now so the GraphQL enum does not change in later chunks.
export const INGESTION_HEALTH_STATUSES = ['healthy', 'idle', 'degraded', 'critical', 'stopped', 'unknown'] as const;
export type IngestionHealthStatus = typeof INGESTION_HEALTH_STATUSES[number];

// runtime checks decide the status, configuration warnings never do (RFC 0001 §4.1, §5.1)
export type IngestionCheckKind = 'runtime' | 'configuration';
export type IngestionCheckSeverity = 'advisory' | 'blocking';
export type IngestionCheckCode = 'NO_HEARTBEAT' | 'USER_NOT_SERVICE_ACCOUNT';

export interface IngestionCheck {
  kind: IngestionCheckKind;
  code: IngestionCheckCode;
  severity: IngestionCheckSeverity;
  // Values of the message placeholders, so a surface can render the check in its own locale later
  params: Record<string, string>;
  // English sentence, for logs, API clients and the UI tooltips
  message: string;
}

export interface IngestionHealth {
  status: IngestionHealthStatus;
  // The most diagnostic check as one sentence, or what is known about the source when nothing failed
  summary: string;
  // Runtime checks only, most diagnostic first
  checks: IngestionCheck[];
  // Since when the source is in this status, when known
  since?: Date | null;
}

// The user the source acts as. No name: the warning must not leak it (see computeIngestionWarnings)
export interface IngestionActingUser {
  service_account: boolean;
}

// What the manager remembers of a connector heartbeat between two cycles (Redis, RFC 0001 §4.4)
export interface HeartbeatObservation {
  last_seen_at: string | null; // last ping observed, ISO date
  close_pings: number; // pings observed in a row, each within the close-pings bound of the previous one
}

// Everything the runtime evaluation needs, extracted from the source, its observation and the platform caches
export interface IngestionHealthInput {
  running: boolean; // false when switched off by a person
  run_and_terminate: boolean; // declared as absent between its runs
  last_seen_at: Date | null; // last ping, null when never seen or unreadable
  pings_regularly: boolean; // seen pinging every 40 seconds, false for a connector pinging only at start and exit
}
