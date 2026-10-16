import { z } from 'zod';
import { IngestionHealthCheckKind, IngestionHealthCheckSeverity } from '../../generated/graphql';
import { ENTITY_TYPE_CONNECTOR } from '../../schema/internalObject';
import { CONNECTOR_LIVELINESS_GRACE_PERIOD_MS } from '../connector/connector-types';
import { durationInMs } from '../../utils/format';
import type { RuntimeDataStorageConfig } from './ingestionHealthRuntimeData-storage';

export const HEALTH_CHECK_USER_MISSING = 'USER_MISSING';
export const HEALTH_CHECK_HEARTBEAT_MISSING = 'HEARTBEAT_MISSING';

// The ingestor evaluated: a connector, a feed or a sync
export interface HealthCheckIngestor {
  internal_id: string;
  entity_type: string;
  built_in?: boolean;
  // The user of a connector
  connector_user_id?: string | null;
  // The user of a feed or a sync
  user_id?: string | null;
}

// What decides whether a check applies, computed once at the beginning of each period of the ingestion health manager
export interface HealthCheckEnablingContext extends Pick<HealthContext, 'isStopped'> {
  // Connectors pinging continuously
  pingingConnectorsIds: Set<string>;
}

// What the evaluation looks at, besides the configuration of the ingestion.
// A new check needing a new fact adds a field here, not a parameter to every function.
export interface HealthContext {
  // The moment of the evaluation: what is stale is judged against it
  evaluatedAt: string;
  // Data reported by the sources, as stored: whether it is still fresh is judged here, not by the storage
  runtimeData?: RuntimeData;
  // Stopped on purpose (by the composer, or a feed or sync switched off): wins over every check
  isStopped?: boolean;
}

export interface HealthChecksContext extends HealthContext, HealthCheckEnablingContext {
  isExistingUser: (userId: string) => boolean;
}

// What describes one occurrence of a failing check, stored with it in Elasticsearch (health_check_metadata) and given back to message().
// Keep it a state, not a measure: it is compared at each period, a value changing every time (a date, a counter) rewrites the ingestion every time.
export type HealthCheckMetadata = Record<string, unknown>;

interface BaseHealthCheckDefinition {
  severity: IngestionHealthCheckSeverity;
  message: (metadata: HealthCheckMetadata) => string;
  // Whether the ingestor is evaluated for this check
  isEnabled: (ingestor: HealthCheckIngestor, context: HealthCheckEnablingContext) => boolean;
}

// getFailure returns null when the check passes, and the metadata of the failure when it fails ({} when there is nothing to tell)
interface ConfigurationCheckDefinition extends BaseHealthCheckDefinition {
  kind: IngestionHealthCheckKind.Configuration;
  getFailure: (ingestor: HealthCheckIngestor, context: HealthChecksContext) => HealthCheckMetadata | null;
}

// A runtime check is judged from a value reported by the sources: the name of its entry in RUNTIME_DATA.
// The value is undefined when the sources reported nothing.
// Its isEnabled must be false for a stopped ingestor: nothing is read for it, a missing value would be reported as a failure.
type RuntimeCheckDefinition = {
  [T in RuntimeDataType]: BaseHealthCheckDefinition & {
    kind: IngestionHealthCheckKind.Runtime;
    runtimeData: T;
    getFailure: (value: RuntimeDataValue<T> | undefined, context: HealthChecksContext) => HealthCheckMetadata | null;
  };
}[RuntimeDataType];

export type HealthCheckDefinition = ConfigurationCheckDefinition | RuntimeCheckDefinition;

// region runtime data
// The format of a value reported by the sources and where it is stored.
// Values are stored as reported, what is stale or missing is up to the ingestion health manager.
// Changing the storage of a runtime data is changing its `storage` line, see ingestionHealthRuntimeData-storage.
interface RuntimeDataDefinition {
  schema: z.ZodType;
  storage: RuntimeDataStorageConfig;
}

export const RUNTIME_DATA = {
  // Last time a connector pinged or registered (ISO date).
  // Kept in the sorted set of the connector liveness: it has no expiration, the age of the value is judged by the manager.
  heartbeat: {
    schema: z.iso.datetime(),
    storage: {
      type: 'redis_sorted_set',
      key: 'connector_heartbeats',
      toScore: (iso: string) => new Date(iso).getTime(),
      fromScore: (epochMs: number) => new Date(epochMs).toISOString(),
    },
  },
} as const satisfies Record<string, RuntimeDataDefinition>;

export type RuntimeDataType = keyof typeof RUNTIME_DATA;
export type RuntimeDataValue<T extends RuntimeDataType> = z.infer<(typeof RUNTIME_DATA)[T]['schema']>;
export type RuntimeData = { [T in RuntimeDataType]?: RuntimeDataValue<T> };
export const RUNTIME_DATA_TYPES = Object.keys(RUNTIME_DATA) as RuntimeDataType[];
// endregion

// Built-in connectors (feed twins) are not deployed: no process runs them
const isDeployed = (ingestor: HealthCheckIngestor) => !ingestor.built_in;

// Connectors authenticate with their own user; feeds and syncs without one run as the system user, a supported setup
const isUserRequired = (ingestor: HealthCheckIngestor) => ingestor.entity_type === ENTITY_TYPE_CONNECTOR;

const getIngestorUserId = (ingestor: HealthCheckIngestor) => {
  return ingestor.entity_type === ENTITY_TYPE_CONNECTOR ? ingestor.connector_user_id : ingestor.user_id;
};

// Same window as the connector liveness (isConnectorActive).
// A heartbeat in the future (clock skew between nodes) is alive
export const isHeartbeatAlive = (heartbeat: string | undefined, evaluatedAt: string): boolean => {
  if (!heartbeat) {
    return false;
  }
  return durationInMs(heartbeat, evaluatedAt) < CONNECTOR_LIVELINESS_GRACE_PERIOD_MS;
};

// Kind, severity and message describe the type of check, not one occurrence: they are never stored,
// so changing them never requires rewriting Elasticsearch.
export const HEALTH_CHECK_REGISTRY = {
  // No user id or name in the message: reading a connector only needs MODULES, its user is reserved to SETTINGS_SETACCESSES
  [HEALTH_CHECK_USER_MISSING]: {
    kind: IngestionHealthCheckKind.Configuration,
    severity: IngestionHealthCheckSeverity.Blocking,
    message: () => 'User is missing',
    // A required user, or an optional one that was set: it must exist
    isEnabled: (ingestor) => isDeployed(ingestor) && isUserRequired(ingestor),
    getFailure: (ingestor, { isExistingUser }) => {
      const userId = getIngestorUserId(ingestor);
      return !userId || !isExistingUser(userId) ? {} : null;
    },
  },
  // A running process pings regularly: no heartbeat means it is down
  [HEALTH_CHECK_HEARTBEAT_MISSING]: {
    kind: IngestionHealthCheckKind.Runtime,
    severity: IngestionHealthCheckSeverity.Blocking,
    message: () => 'No heartbeat received',
    // Only the running connectors pinging continuously: the others would be missing their heartbeat between two runs
    isEnabled: (ingestor, { isStopped, pingingConnectorsIds }) => !isStopped && isDeployed(ingestor) && pingingConnectorsIds.has(ingestor.internal_id),
    runtimeData: 'heartbeat',
    getFailure: (heartbeat, { evaluatedAt }) => (isHeartbeatAlive(heartbeat, evaluatedAt) ? null : {}),
  },
} as const satisfies Record<string, HealthCheckDefinition>;

export type HealthCheckCode = keyof typeof HEALTH_CHECK_REGISTRY;

// A code read from storage can be unknown to this platform version
export const getHealthCheckDefinition = (code: string): HealthCheckDefinition | undefined => {
  return (HEALTH_CHECK_REGISTRY as Record<string, HealthCheckDefinition>)[code];
};
