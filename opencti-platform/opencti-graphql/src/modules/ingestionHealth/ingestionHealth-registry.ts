import { IngestionHealthCheckKind, IngestionHealthCheckSeverity } from '../../generated/graphql';
import { ENTITY_TYPE_CONNECTOR } from '../../schema/internalObject';
import { CONNECTOR_LIVELINESS_GRACE_PERIOD_MS } from '../connector/connector-types';
import { durationInMs } from '../../utils/format';
import { redisGetConnectorsHeartbeats } from '../connector/connector-redis';

export const HEALTH_CHECK_USER_MISSING = 'USER_MISSING';
export const HEALTH_CHECK_HEARTBEAT_MISSING = 'HEARTBEAT_MISSING';

// Every check of the registry: adding a check adds its code here
export type HealthCheckCode = typeof HEALTH_CHECK_USER_MISSING
  | typeof HEALTH_CHECK_HEARTBEAT_MISSING;

// The values read by the runtime checks for one ingestion, by check code.
// Inferred from the registry: the type of each value is the one returned by the getRuntimeData of its check
type Registry = typeof HEALTH_CHECK_REGISTRY;
type RuntimeCheckCode = { [C in HealthCheckCode]: Registry[C] extends RuntimeCheckDefinition<any> ? C : never }[HealthCheckCode];
// The runtime checks of the registry, each with the type of its value: a union when they read different types
export type RuntimeCheck = Extract<Registry[HealthCheckCode], { kind: IngestionHealthCheckKind.Runtime }>;
export type RuntimeData = { [C in RuntimeCheckCode]?: Registry[C] extends RuntimeCheckDefinition<infer T> ? T : never };

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

// Computed once at the beginning of each period of the ingestion health manager, shared by the evaluation of every ingestion
export interface GlobalIngestionHealthContext {
  // The moment of the evaluation: what is stale is judged against it
  evaluatedAt: string;
  // Connectors pinging continuously
  pingingConnectorsIds: Set<string>;
  isExistingUser: (userId: string) => boolean;
}

// What the evaluation looks at, besides the configuration of the ingestion: whether a check applies, whether it fails, the status.
// A new check needing a new fact adds a field here, not a parameter to every function.
export interface SourceIngestionHealthContext extends GlobalIngestionHealthContext {
  // Values read by the runtime checks enabled for this ingestion, by check code: whether they are still fresh is judged here, not when read
  runtimeData?: RuntimeData;
}

// What describes one occurrence of a failing check, stored with it in Elasticsearch (health_check_metadata) and given back to message().
// Keep it a state, not a measure: it is compared at each period, a value changing every time (a date, a counter) rewrites the ingestion every time.
export type HealthCheckMetadata = Record<string, unknown>;

interface BaseHealthCheckDefinition {
  severity: IngestionHealthCheckSeverity;
  message: (metadata: HealthCheckMetadata) => string;
  // Whether the ingestor is evaluated for this check
  isEnabled: (ingestor: HealthCheckIngestor, context: SourceIngestionHealthContext) => boolean;
}

// getFailure returns null when the check passes, and the metadata of the failure when it fails ({} when there is nothing to tell)
interface ConfigurationCheckDefinition extends BaseHealthCheckDefinition {
  kind: IngestionHealthCheckKind.Configuration;
  getFailure: (ingestor: HealthCheckIngestor, context: SourceIngestionHealthContext) => HealthCheckMetadata | null;
}

// A runtime check is judged from a value reported by the sources, read by its getRuntimeData.
// getRuntimeData reads the values of every ingestion at once, by ingestion id: it is called once per source by the ingestion health manager.
// It returns what was reported, as stored: what is stale is judged by getFailure. Absent ingestions are omitted.
// The value given to getFailure is undefined when the sources reported nothing.
// Its isEnabled must be false for a stopped ingestor: nothing is read for it, a missing value would be reported as a failure.
export interface RuntimeCheckDefinition<T> extends BaseHealthCheckDefinition {
  kind: IngestionHealthCheckKind.Runtime;
  getRuntimeData: () => Promise<Map<string, T>>;
  getFailure: (value: T | undefined, context: SourceIngestionHealthContext) => HealthCheckMetadata | null;
}

// The type of the value is inferred from getRuntimeData, so that getFailure is checked against it
const defineRuntimeCheck = <T>(definition: RuntimeCheckDefinition<T>): RuntimeCheckDefinition<T> => definition;

export type HealthCheckDefinition = ConfigurationCheckDefinition | RuntimeCheckDefinition<any>;

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
// Not annotated but checked with satisfies: the annotation would widen every check to HealthCheckDefinition,
// losing the type of the runtime values that RuntimeData is inferred from
export const HEALTH_CHECK_REGISTRY = {
  // No user id or name in the message: reading a connector only needs MODULES, its user is reserved to SETTINGS_SETACCESSES
  [HEALTH_CHECK_USER_MISSING]: {
    kind: IngestionHealthCheckKind.Configuration,
    severity: IngestionHealthCheckSeverity.Blocking,
    message: () => 'User is missing',
    // A required user, or an optional one that was set: it must exist
    isEnabled: (ingestor) => isDeployed(ingestor) && (isUserRequired(ingestor) || !!getIngestorUserId(ingestor)),
    getFailure: (ingestor, { isExistingUser }) => {
      const userId = getIngestorUserId(ingestor);
      return !userId || !isExistingUser(userId) ? {} : null;
    },
  },
  // A running process pings regularly: no heartbeat means it is down
  [HEALTH_CHECK_HEARTBEAT_MISSING]: defineRuntimeCheck({
    kind: IngestionHealthCheckKind.Runtime,
    severity: IngestionHealthCheckSeverity.Blocking,
    message: () => 'No heartbeat received',
    // Only the running connectors pinging continuously: the others would be missing their heartbeat between two runs
    isEnabled: (ingestor, { pingingConnectorsIds }) => isDeployed(ingestor) && pingingConnectorsIds.has(ingestor.internal_id),
    getRuntimeData: redisGetConnectorsHeartbeats,
    getFailure: (heartbeat, { evaluatedAt }) => (isHeartbeatAlive(heartbeat, evaluatedAt) ? null : {}),
  }),
} satisfies Record<HealthCheckCode, HealthCheckDefinition>;
