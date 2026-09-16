// Ingestion health — model types.
//
// Shared by the evaluator, the domain layer and the resolver. Kept free of
// imports from the rest of the platform so the evaluator stays pure and
// unit-testable without a running platform.

import type { CheckParams, IngestionCheckCode } from './ingestionHealth-messages';

export type IngestionHealthStatus = 'healthy' | 'idle' | 'degraded' | 'critical' | 'stopped' | 'unknown';

export type IngestionCheckKind = 'runtime'; // 'configuration' added by increment 3
export type IngestionCheckSeverity = 'advisory' | 'blocking';

export interface IngestionCheck {
  kind: IngestionCheckKind;
  code: IngestionCheckCode;
  severity: IngestionCheckSeverity;
  params: CheckParams;
  message: string;
  detail?: string;
}

export interface IngestionHealth {
  status: IngestionHealthStatus;
  summary: string;
  checks: IngestionCheck[];
  since?: Date;
  last_productive_at?: Date;
  next_expected_at?: Date;
}

// What the manager persists between cycles and reads back on the next one.
//
// This lives in Redis, not Elasticsearch, and on purpose: it is the manager's
// own memory — the state needed to tell "just went critical" apart from "has
// been critical for six hours" — not a queryable fact about the source. The
// health *status* is never stored anywhere; it is recomputed from live facts on
// every read. If health ever needs to be filtered or sorted server-side, that is
// a separate set of Elastic attributes on each source (spec D2), not this.
//
// Declared here rather than next to the Redis helpers so the evaluator, the
// manager and the resolver all agree on one shape.
export interface IngestionHealthObservation {
  status: IngestionHealthStatus;
  since: string;
  last_productive_at?: string;
  // The run these counters were last advanced for. Empty runs are counted per
  // *run*, never per evaluation: the manager evaluates every 60s while a daily
  // feed runs once a day, so a cycle that sees no new run carries them forward.
  last_run_at?: string;
  last_cursor_hash?: string;
  consecutive_empty_runs: number;
  last_alert_at?: string;
  // Hysteresis: how many consecutive evaluations have agreed on a status that
  // has not been published yet.
  pending_status?: IngestionHealthStatus;
  pending_count?: number;
}

export type IngestionSourceKind = 'connector' | 'feed' | 'sync';

// A normalized view of any ingestion source. The manager is responsible for
// mapping connectors, the five feed types and synchronizers onto this shape;
// this module never knows which entity it came from.
export interface IngestionHealthInput {
  id: string;
  name: string;
  source_kind: IngestionSourceKind;

  // connector-only shape hints, used to pick the rule profile
  connector_type?: string;
  auto?: boolean;
  run_and_terminate?: boolean;

  // liveness
  enabled: boolean; // active | ingestion_running | running
  manually_stopped?: boolean;
  last_seen_at?: Date; // updated_at | connector_state_timestamp
  heartbeat_interval_seconds?: number;
  // `consumers` is undefined when RabbitMQ could not be read. The evaluator
  // treats that as "unknown" and skips NO_CONSUMER rather than reporting every
  // connector as broken during a broker outage.
  queue?: { messages_ready: number; consumers?: number; idle_since?: Date };

  // productivity
  created_at?: Date;
  last_run_at?: Date;
  next_expected_at?: Date;
  expected_period_seconds?: number;
  last_run_failed?: boolean;
  last_run_error?: string;
  last_productive_at?: Date;
  consecutive_empty_runs?: number;
  cursor_hash?: string;

  previous?: IngestionHealthObservation;
}

export interface IngestionHealthThresholds {
  missedPeriodsBeforeAlert: number; // periods, for sources that declare one
  emptyRunsBeforeAlert: number;
  heartbeatGraceSeconds: number;
  evaluationIntervalSeconds: number;
  // Tolerance for a source that declares no schedule ("auto" feeds, syncs).
  // It must clear the manager's own floor — `ingestion_manager:csv_feed:
  // min_interval_minutes` defaults to 5 — or a perfectly healthy auto feed is
  // reported stale between two of its own runs.
  unscheduledStaleSeconds: number;
}

export const DEFAULT_THRESHOLDS: IngestionHealthThresholds = {
  missedPeriodsBeforeAlert: 2,
  emptyRunsBeforeAlert: 3,
  heartbeatGraceSeconds: 300, // grace is 2× this
  evaluationIntervalSeconds: 60,
  unscheduledStaleSeconds: 3600,
};
