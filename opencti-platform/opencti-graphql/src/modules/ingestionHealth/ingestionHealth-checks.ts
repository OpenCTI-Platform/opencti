import * as R from 'ramda';
import { type IngestionHealth, type IngestionHealthCheck, IngestionHealthCheckKind, IngestionHealthCheckSeverity, IngestionHealthStatus } from '../../generated/graphql';
import type { IngestionHealthFields, StoredHealthCheck, StoredIngestionHealth } from './ingestionHealth-types';
import {
  getHealthCheckDefinition,
  HEALTH_CHECK_REGISTRY,
  type HealthCheckCode,
  type HealthCheckDefinition,
  type HealthCheckMetadata,
  type HealthChecksContext,
  type HealthCheckIngestor,
  type HealthContext,
  isHeartbeatAlive,
} from './ingestionHealth-registry';

// region evaluation (pure, no I/O)
const getFailure = (definition: HealthCheckDefinition, ingestor: HealthCheckIngestor, context: HealthChecksContext): HealthCheckMetadata | null => {
  if (definition.kind === IngestionHealthCheckKind.Runtime) {
    // The value type depends on the runtime data of each check, which a loop over all the checks cannot express: it is checked where the check is declared
    const getRuntimeFailure = definition.getFailure as (value: unknown, context: HealthChecksContext) => HealthCheckMetadata | null;
    return getRuntimeFailure(context.runtimeData?.[definition.runtimeData], context);
  }
  return definition.getFailure(ingestor, context);
};

export const computeIngestionHealthChecks = (ingestor: HealthCheckIngestor, context: HealthChecksContext): StoredHealthCheck[] => {
  return (Object.entries(HEALTH_CHECK_REGISTRY) as [HealthCheckCode, HealthCheckDefinition][]).flatMap(([code, definition]) => {
    const metadata = definition.isEnabled(ingestor, context) ? getFailure(definition, ingestor, context) : null;
    return metadata ? [{ health_check_code: code, health_check_metadata: metadata }] : [];
  });
};

// Priority: stopped > critical > degraded > healthy. A stopped ingestion keeps its configuration checks, they do not change its status.
// Unknown is not a status: it is the absence of ingestion_health, before the first evaluation.
export const computeHealthStatus = (checks: StoredHealthCheck[], { evaluatedAt, runtimeData = {}, isStopped }: HealthContext): IngestionHealthStatus | null => {
  if (isStopped) {
    return IngestionHealthStatus.Stopped;
  }
  // A code unknown to this platform version has no definition: it cannot change the status
  const healthChecks = checks
    .map((check) => getHealthCheckDefinition(check.health_check_code))
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
  Stopped: 'stopped',
} as const;
export type HealthTransition = typeof HealthTransition[keyof typeof HealthTransition];

// previous is undefined on the first evaluation: a failing ingestion is reported, a healthy one has nothing to recover from.
// next is undefined when the health object is removed because no status can be computed anymore (no more failing check):
// it is a recovery only for an ingestion that was failing.
// A stop is reported only when it ends a monitored status: an ingestion already stopped at its first evaluation is not.
// A restart is reported only when it fails: a stopped ingestion was not failing, it has nothing to recover from.
export const computeHealthTransition = (previous: IngestionHealthStatus | undefined, next: IngestionHealthStatus | undefined): HealthTransition | null => {
  if (previous === next) {
    return null;
  }
  if (next === IngestionHealthStatus.Stopped) {
    return previous ? HealthTransition.Stopped : null;
  }
  if (next === IngestionHealthStatus.Critical) {
    return HealthTransition.Critical;
  }
  if (next === IngestionHealthStatus.Degraded) {
    return HealthTransition.Degraded;
  }
  const wasFailing = previous === IngestionHealthStatus.Critical || previous === IngestionHealthStatus.Degraded;
  if (wasFailing && (next === IngestionHealthStatus.Healthy || !next)) {
    return HealthTransition.Recovered;
  }
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
export const toGraphqlHealthChecks = (checks: StoredHealthCheck[] | undefined): IngestionHealthCheck[] => {
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
