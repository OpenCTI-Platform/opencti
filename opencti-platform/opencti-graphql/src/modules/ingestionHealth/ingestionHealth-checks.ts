import * as R from 'ramda';
import { type IngestionHealth, type IngestionHealthCheck, IngestionHealthCheckKind, IngestionHealthCheckSeverity, IngestionHealthStatus } from '../../generated/graphql';
import { HealthTransition, type IngestionHealthFields, type StoredHealthCheck, type StoredIngestionHealth } from './ingestionHealth-types';
import {
  HEALTH_CHECK_HEARTBEAT_MISSING,
  HEALTH_CHECK_REGISTRY,
  type HealthCheckCode,
  type GlobalIngestionHealthContext,
  type HealthCheckDefinition,
  type HealthCheckMetadata,
  type HealthCheckIngestor,
  type RuntimeData,
  type SourceIngestionHealthContext,
  isHeartbeatAlive,
} from './ingestionHealth-registry';

// A stored code can be unknown to this platform version (written by another one): undefined then
const findHealthCheckDefinition = (code: string): HealthCheckDefinition | undefined => {
  return HEALTH_CHECK_REGISTRY[code as HealthCheckCode] as HealthCheckDefinition | undefined;
};

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

// Whether a runtime check is enabled for the ingestor: its runtime data must be read before it is evaluated
export const isRuntimeCheckEnabled = (ingestor: HealthCheckIngestor, context: GlobalIngestionHealthContext): boolean => {
  return Object.values(HEALTH_CHECK_REGISTRY).some((definition) => definition.kind === IngestionHealthCheckKind.Runtime
    && definition.isEnabled(ingestor, context));
};

// Keeps only the runtime values of the checks enabled for the ingestor: a value read for a disabled check proves nothing.
// A connector not pinging continuously still leaves a heartbeat after each run: kept, it would be healthy after every run.
export const buildIngestionHealthContext = (
  ingestor: HealthCheckIngestor,
  context: SourceIngestionHealthContext,
): SourceIngestionHealthContext => {
  const runtimeData: RuntimeData = context.runtimeData ?? {};
  const enabledRuntimeData: RuntimeData = R.pickBy((_, code) => HEALTH_CHECK_REGISTRY[code as HealthCheckCode].isEnabled(ingestor, context), runtimeData);
  return { ...context, runtimeData: enabledRuntimeData };
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
// Unknown when no status can be computed: no proof of life nor failure.
export const computeHealthStatus = (checks: StoredHealthCheck[], { evaluatedAt, runtimeData = {} }: SourceIngestionHealthContext): IngestionHealthStatus => {
  // A code unknown to this platform version has no definition: it cannot change the status
  const healthChecks = checks
    .map((check) => findHealthCheckDefinition(check.health_check_code))
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
  // healthy needs a proof of life from the runtime data AND no check at all, otherwise the status stays unknown.
  // The runtime data only holds the values of the checks enabled for the ingestor (see buildIngestionHealthContext)
  if (checks.length === 0 && isHeartbeatAlive(runtimeData[HEALTH_CHECK_HEARTBEAT_MISSING], evaluatedAt)) {
    return IngestionHealthStatus.Healthy;
  }
  return IngestionHealthStatus.Unknown;
};

const normalizeHealthChecks = (checks: StoredHealthCheck[]): StoredHealthCheck[] => {
  const normalized = checks.map((check) => ({ health_check_code: check.health_check_code, health_check_metadata: check.health_check_metadata ?? {} }));
  return normalized.sort((a, b) => a.health_check_code.localeCompare(b.health_check_code));
};

// Returns the fields to write, or null when neither the status nor the checks changed.
// The write replaces the whole ingestion_health object, so it carries the unchanged since.
// Unknown is stored like any status, from the first evaluation: since moves, and its recovery is notified after the delay like any status.
export const computeIngestionHealthPatch = (
  current: IngestionHealthFields,
  checks: StoredHealthCheck[],
  context: SourceIngestionHealthContext,
): IngestionHealthFields | null => {
  const { evaluatedAt } = context;
  const currentHealth = current.ingestion_health;
  const status = computeHealthStatus(checks, context);
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
      // Kept across status changes: the last event tells whether the current status was already notified, and whether a recovery is due
      ...(currentHealth?.last_event_date ? { last_event_date: currentHealth.last_event_date } : {}),
      ...(currentHealth?.last_event_status ? { last_event_status: currentHealth.last_event_status } : {}),
    },
  };
};

// region transition

// Default of the notification delay, editable in the ingestion health settings of the platform
export const DEFAULT_HEALTH_NOTIFICATION_DELAY_MS = 5 * 60 * 1000;

const isFailureStatus = (status: IngestionHealthStatus | undefined) => status === IngestionHealthStatus.Critical
  || status === IngestionHealthStatus.Degraded;

/**
 * Computes the health activity event to publish for an ingestion, evaluated at every period of the ingestion health manager.
 *
 * The event is deferred to avoid notifying a flapping status: it is due once the status has not changed
 * for the notification delay, and differs from the status reported by the last event published (last_event_status).
 * Going back to the reported status inside the delay reports nothing: the last event already tells it.
 *
 * Healthy and unknown end a failure: their recovery is reported only when the last event published reports a failure,
 * even when the failure just before (shorter than the delay) was never reported itself.
 * So nothing is reported between unknown and healthy, nor twice for the same recovery.
 *
 * A stopped ingestion is not evaluated: its health is removed and nothing is reported.
 *
 * @param health health after the write of this period, absent when never evaluated or stopped
 * @param evaluatedAt date of the evaluation period
 * @param notificationDelay ms a status must stay unchanged before it is notified
 * @returns the transition to publish, or null when nothing is due
 */
export const computeHealthTransition = (
  health: StoredIngestionHealth | null | undefined,
  evaluatedAt: string,
  notificationDelay = DEFAULT_HEALTH_NOTIFICATION_DELAY_MS,
): HealthTransition | null => {
  // The last event published already reports the current status: one event per status change
  if (!health || health.last_event_status === health.status) {
    return null;
  }
  // The status changed less than the delay ago: it may still flap, wait for the next periods
  if (new Date(evaluatedAt).getTime() - new Date(health.status_since).getTime() < notificationDelay) {
    return null;
  }
  // Stable failing status not reported by the last event: report it
  if (health.status === IngestionHealthStatus.Critical) {
    return HealthTransition.Critical;
  }
  if (health.status === IngestionHealthStatus.Degraded) {
    return HealthTransition.Degraded;
  }
  // Stable healthy or unknown status: a recovery only when the last event reports a failure.
  // No event yet (new, restarted) or the last one already a recovery, there is nothing to recover from
  return isFailureStatus(health.last_event_status) ? HealthTransition.Recovered : null;
};

// The health to write once the event is published: it becomes the last event, whatever its transition
export const markHealthNotified = (health: StoredIngestionHealth, evaluatedAt: string): StoredIngestionHealth => (
  { ...health, last_event_date: evaluatedAt, last_event_status: health.status }
);

// The activity log prefixes the message with the manager user name
export const buildHealthTransitionMessage = (element: { name: string; entity_type: string }, transition: HealthTransition, checks: StoredHealthCheck[]) => {
  const checkMessages = toGraphqlHealthChecks(checks, element.entity_type).map((check) => check.health_check_message);
  const details = checkMessages.length > 0 ? `: ${checkMessages.join(', ')}` : '';
  return `reports \`${element.name}\` (${element.entity_type}) as ${transition}${details}`;
};
// endregion

// region api
// The entity type of the ingestor carrying the checks adapts their messages to the kind of ingestion
export const toGraphqlHealthChecks = (checks: StoredHealthCheck[] | undefined, entityType: string): IngestionHealthCheck[] => {
  return (checks ?? []).flatMap((check) => {
    const definition = findHealthCheckDefinition(check.health_check_code);
    if (!definition) {
      // Code unknown to this platform version: nothing reliable to show
      return [];
    }
    return [{
      health_check_code: check.health_check_code,
      health_check_message: definition.message(check.health_check_metadata ?? {}, entityType),
      health_check_kind: definition.kind,
      health_check_severity: definition.severity,
    }];
  });
};

// Read from Elasticsearch only, never from Redis: the lists of ingestions are polled.
// Null until the manager first evaluates the ingestion, which reads as unknown.
export const toGraphqlIngestionHealth = (health: StoredIngestionHealth | null | undefined, entityType: string): IngestionHealth | null => {
  if (!health) {
    return null;
  }
  return {
    status: health.status,
    status_since: health.status_since,
    healthChecks: toGraphqlHealthChecks(health.health_checks, entityType),
  };
};
// endregion
