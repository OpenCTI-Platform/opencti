import * as R from 'ramda';
import { type IngestionHealth, type IngestionHealthCheck, IngestionHealthCheckKind, IngestionHealthCheckSeverity, IngestionHealthStatus } from '../../generated/graphql';
import type { IngestionHealthFields, StoredHealthCheck, StoredIngestionHealth } from './ingestionHealth-types';
import {
  HEALTH_CHECK_HEARTBEAT_MISSING,
  HEALTH_CHECK_REGISTRY,
  type HealthCheckCode,
  type HealthCheckDefinition,
  type HealthCheckMetadata,
  type HealthCheckIngestor,
  type SourceIngestionHealthContext,
  isHeartbeatAlive,
} from './ingestionHealth-registry';

// region evaluation (pure, no I/O)
/**
 * Runs one check against one ingestor, giving its getFailure what the kind of the check judges:
 * the ingestor itself for a configuration check, the value read for this check for a runtime check.
 *
 * @param code the code of the check, under which its runtime value is found in context.runtimeData
 * @param definition the check, whose isEnabled is already true for the ingestor
 * @param ingestor the connector, feed or sync evaluated
 * @param context the evaluation context, holding the runtime values of the ingestor
 * @returns null when the check passes; the metadata of the failure when it fails, {} when there is nothing to tell
 */
const getHealthCheckFailure = (
  code: HealthCheckCode,
  definition: HealthCheckDefinition,
  ingestor: HealthCheckIngestor,
  context: SourceIngestionHealthContext,
): HealthCheckMetadata | null => {
  if (definition.kind === IngestionHealthCheckKind.Runtime) {
    // The value type depends on each check, which a loop over all the checks cannot express: it is checked where the check is declared
    const runtimeData: Record<string, unknown> = context.runtimeData ?? {};
    return definition.getFailure(runtimeData[code], context);
  }
  return definition.getFailure(ingestor, context);
};

export const computeIngestionHealthChecks = (
  ingestor: HealthCheckIngestor,
  context: SourceIngestionHealthContext,
): StoredHealthCheck[] => {
  return (Object.entries(HEALTH_CHECK_REGISTRY) as [HealthCheckCode, HealthCheckDefinition][]).flatMap(([code, definition]) => {
    const metadata = definition.isEnabled(ingestor, context) ? getHealthCheckFailure(code, definition, ingestor, context) : null;
    return metadata ? [{ health_check_code: code, health_check_metadata: metadata }] : [];
  });
};

// Priority: critical > degraded > healthy. A stopped ingestion is never evaluated (see the ingestion health manager).
// Unknown is not a status: it is the absence of ingestion_health, before the first evaluation.
export const computeHealthStatus = (checks: StoredHealthCheck[], { evaluatedAt, runtimeData = {} }: SourceIngestionHealthContext): IngestionHealthStatus | null => {
  // A code unknown to this platform version has no definition: it cannot change the status
  const healthChecks = checks
    .map((check) => HEALTH_CHECK_REGISTRY[check.health_check_code])
    .filter((definition) => !!definition);
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
  if (checks.length === 0 && isHeartbeatAlive(runtimeData[HEALTH_CHECK_HEARTBEAT_MISSING], evaluatedAt)) {
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
  context: SourceIngestionHealthContext,
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
// A stopped ingestion is not evaluated: its health is removed and nothing is reported.
// A restart is reported only when it fails: a stopped ingestion has no health, it has nothing to recover from.
export const computeHealthTransition = (
  previous: IngestionHealthStatus | undefined,
  next: IngestionHealthStatus | undefined,
): HealthTransition | null => {
  if (previous === next) {
    return null;
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
