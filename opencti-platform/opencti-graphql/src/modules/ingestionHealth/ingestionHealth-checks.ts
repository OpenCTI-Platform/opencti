import * as R from 'ramda';
import { type IngestionHealth, type IngestionHealthCheck, IngestionHealthCheckKind, IngestionHealthCheckSeverity, IngestionHealthStatus } from '../../generated/graphql';
import type { IngestionHealthFields, StoredHealthCheck, StoredIngestionHealth } from './ingestionHealth-types';
import type { RuntimeData } from './ingestionHealthRuntimeData';
import { CONNECTOR_LIVELINESS_GRACE_PERIOD_MS } from '../connector/connector-types';
import { durationInMs } from '../../utils/format';
import { ENTITY_TYPE_CONNECTOR } from '../../schema/internalObject';

// region registry
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

const getIngestorUserId = (ingestor: HealthCheckIngestor) => {
  return ingestor.entity_type === ENTITY_TYPE_CONNECTOR ? ingestor.connector_user_id : ingestor.user_id;
};

// Connectors authenticate with their own user; feeds and syncs without one run as the system user, a supported setup
const isUserRequired = (ingestor: HealthCheckIngestor) => ingestor.entity_type === ENTITY_TYPE_CONNECTOR;

// What decides whether a check applies, computed once at the beginning of each period of the ingestion health manager
export interface HealthCheckEnablingContext {
  // Connectors pinging continuously
  pingingConnectorsIds: Set<string>;
}

interface HealthCheckDefinition {
  kind: IngestionHealthCheckKind;
  severity: IngestionHealthCheckSeverity;
  message: (metadata: Record<string, unknown>) => string;
  // Whether the ingestor is evaluated for this check
  isEnabled: (ingestor: HealthCheckIngestor, context: HealthCheckEnablingContext) => boolean;
}

// Built-in connectors (feed twins) are not deployed: no process runs them
const isDeployed = (ingestor: HealthCheckIngestor) => !ingestor.built_in;

// Kind, severity and message describe the type of check, not one occurrence: they are never stored,
// so changing them never requires rewriting Elasticsearch.
const HEALTH_CHECK_REGISTRY: Record<string, HealthCheckDefinition> = {
  // No user id or name in the message: reading a connector only needs MODULES, its user is reserved to SETTINGS_SETACCESSES
  [HEALTH_CHECK_USER_MISSING]: {
    kind: IngestionHealthCheckKind.Configuration,
    severity: IngestionHealthCheckSeverity.Blocking,
    message: () => 'User is missing',
    // A required user, or an optional one that was set: it must exist
    isEnabled: (ingestor) => isDeployed(ingestor) && isUserRequired(ingestor),
  },
  // A running process pings regularly: no heartbeat means it is down
  [HEALTH_CHECK_HEARTBEAT_MISSING]: {
    kind: IngestionHealthCheckKind.Runtime,
    severity: IngestionHealthCheckSeverity.Blocking,
    message: () => 'No heartbeat received',
    // Only the connectors pinging continuously: the others would be missing their heartbeat between two runs
    isEnabled: (ingestor, { pingingConnectorsIds }) => isDeployed(ingestor) && pingingConnectorsIds.has(ingestor.internal_id),
  },
};

const isCheckEnabled = (code: string, ingestor: HealthCheckIngestor, context: HealthCheckEnablingContext) => {
  return HEALTH_CHECK_REGISTRY[code].isEnabled(ingestor, context);
};
// endregion

// region evaluation (pure, no I/O)
// What the evaluation looks at, besides the configuration of the ingestion.
// A new check needing a new fact adds a field here, not a parameter to every function.
export interface HealthContext {
  // The moment of the evaluation: what is stale is judged against it
  evaluatedAt: string;
  // Data reported by the sources, as stored: whether it is still fresh is judged here, not by the storage
  runtimeData?: RuntimeData;
}

export interface HealthChecksContext extends HealthContext, HealthCheckEnablingContext {
  isExistingUser: (userId: string) => boolean;
}

// Same window as the connector liveness (isConnectorActive).
// A heartbeat in the future (clock skew between nodes) is alive
export const isHeartbeatAlive = (heartbeat: string | undefined, evaluatedAt: string): boolean => {
  if (!heartbeat) {
    return false;
  }
  return durationInMs(heartbeat, evaluatedAt) < CONNECTOR_LIVELINESS_GRACE_PERIOD_MS;
};

export const computeIngestionHealthChecks = (ingestor: HealthCheckIngestor, context: HealthChecksContext): StoredHealthCheck[] => {
  const { isExistingUser, evaluatedAt, runtimeData } = context;
  const checks: StoredHealthCheck[] = [];
  const userId = getIngestorUserId(ingestor);
  if (isCheckEnabled(HEALTH_CHECK_USER_MISSING, ingestor, context) && (!userId || !isExistingUser(userId))) {
    checks.push({ health_check_code: HEALTH_CHECK_USER_MISSING, health_check_metadata: {} });
  }
  if (isCheckEnabled(HEALTH_CHECK_HEARTBEAT_MISSING, ingestor, context) && !isHeartbeatAlive(runtimeData?.heartbeat, evaluatedAt)) {
    checks.push({ health_check_code: HEALTH_CHECK_HEARTBEAT_MISSING, health_check_metadata: {} });
  }
  return checks;
};

// Priority: critical > degraded > healthy. A stopped ingestion is not monitored, so it never gets here.
// Unknown is not a status: it is the absence of ingestion_health, before the first evaluation.
export const computeHealthStatus = (checks: StoredHealthCheck[], { evaluatedAt, runtimeData = {} }: HealthContext): IngestionHealthStatus | null => {
  // A code unknown to this platform version has no definition: it cannot change the status
  const healthChecks = checks
    .map((check) => HEALTH_CHECK_REGISTRY[check.health_check_code])
    .filter((definition): definition is HealthCheckDefinition => !!definition);
  // blocking AND runtime -> critical
  if (healthChecks.some((definition) => definition.kind === IngestionHealthCheckKind.Runtime
    && definition.severity === IngestionHealthCheckSeverity.Blocking)) {
    return IngestionHealthStatus.Critical;
  }
  // advisory runtime OR advisory/blocking configuration -> degraded
  if (healthChecks.some((definition) => definition.severity === IngestionHealthCheckSeverity.Advisory
    || definition.kind === IngestionHealthCheckKind.Configuration)) {
    return IngestionHealthStatus.Degraded;
  }
  // healthy needs a proof of life from the runtime data AND no check at all, otherwise the status stays unknown
  if (checks.length === 0 && isHeartbeatAlive(runtimeData.heartbeat, evaluatedAt)) {
    return IngestionHealthStatus.Healthy;
  }
  return null;
};

const normalizeHealthChecks = (checks: StoredHealthCheck[]): StoredHealthCheck[] => {
  const normalized = checks.map((check) => ({ health_check_code: check.health_check_code, health_check_metadata: check.health_check_metadata ?? {} }));
  return normalized.sort((a, b) => a.health_check_code.localeCompare(b.health_check_code));
};

// Returns the fields to write, or null when neither the status nor the checks changed.
// The write replaces the whole ingestion_health object, so it carries the unchanged since.
// When no status can be computed anymore, a stored ingestion_health is removed: absence reads as unknown.
export const computeIngestionHealthPatch = (
  current: IngestionHealthFields,
  checks: StoredHealthCheck[],
  context: HealthContext,
): IngestionHealthFields | null => {
  const { evaluatedAt } = context;
  const currentHealth = current.ingestion_health;
  const status = computeHealthStatus(checks, context);
  if (!status) {
    return currentHealth ? { ingestion_health: null } : null;
  }
  const nextChecks = normalizeHealthChecks(checks);
  const isStatusChanged = currentHealth?.status !== status;
  const isChecksChanged = !R.equals(normalizeHealthChecks(currentHealth?.health_checks ?? []), nextChecks);
  if (!isStatusChanged && !isChecksChanged) {
    return null;
  }
  return {
    ingestion_health: {
      status,
      status_since: currentHealth && !isStatusChanged ? currentHealth.status_since : evaluatedAt,
      health_checks: nextChecks,
    },
  };
};

// region transition
// Scope of the activity event published when the status changes
export const HealthTransition = {
  Critical: 'critical',
  Degraded: 'degraded',
  Recovered: 'recovered',
} as const;
export type HealthTransition = typeof HealthTransition[keyof typeof HealthTransition];

// previous is undefined on the first evaluation: a failing ingestion is reported, a healthy one has nothing to recover from.
// next is undefined when the health object is removed because no status can be computed anymore (no more failing check):
// it is a recovery only for an ingestion that was failing.
export const computeHealthTransition = (previous: IngestionHealthStatus | undefined, next: IngestionHealthStatus | undefined): HealthTransition | null => {
  if (previous === next) {
    return null;
  }
  if (next === IngestionHealthStatus.Critical) {
    return HealthTransition.Critical;
  }
  if (next === IngestionHealthStatus.Degraded) {
    return HealthTransition.Degraded;
  }
  if (next === IngestionHealthStatus.Healthy && previous) {
    return HealthTransition.Recovered;
  }
  if (!next && (previous === IngestionHealthStatus.Critical || previous === IngestionHealthStatus.Degraded)) {
    return HealthTransition.Recovered;
  }
  // TODO case of IngestionHealthStatus.Stopped
  return null;
};

// The activity log prefixes the message with the manager user name
export const buildHealthTransitionMessage = (element: { name: string; entity_type: string }, transition: HealthTransition, checks: StoredHealthCheck[]) => {
  const checkMessages = toGraphqlHealthChecks(checks).map((check) => check.health_check_message);
  const details = checkMessages.length > 0 ? `: ${checkMessages.join(', ')}` : '';
  return `reports \`${element.name}\` (${element.entity_type}) as ${transition}${details}`;
};
// endregion

// region api
const toGraphqlHealthChecks = (checks: StoredHealthCheck[] | undefined): IngestionHealthCheck[] => {
  return (checks ?? []).flatMap((check) => {
    const definition = HEALTH_CHECK_REGISTRY[check.health_check_code];
    if (!definition) {
      // Code unknown to this platform version: nothing reliable to show
      return [];
    }
    return [{
      health_check_code: check.health_check_code,
      health_check_message: definition.message(check.health_check_metadata ?? {}),
      health_check_kind: definition.kind,
      health_check_severity: definition.severity,
    }];
  });
};

// Read from Elasticsearch only, never from Redis: the lists of ingestions are polled.
// Null until the manager first evaluates the ingestion, which reads as unknown.
export const toGraphqlIngestionHealth = (health: StoredIngestionHealth | null | undefined): IngestionHealth | null => {
  if (!health) {
    return null;
  }
  return {
    status: health.status,
    status_since: health.status_since,
    healthChecks: toGraphqlHealthChecks(health.health_checks),
  };
};
// endregion
