import * as R from 'ramda';
import { type IngestionHealth, type IngestionHealthCheck, IngestionHealthCheckKind, IngestionHealthCheckSeverity, IngestionHealthStatus } from '../../generated/graphql';
import type { IngestionHealthFields, StoredHealthCheck, StoredIngestionHealth } from './ingestionHealth-types';

// region registry
export const HEALTH_CHECK_USER_MISSING = 'USER_MISSING';

interface HealthCheckDefinition {
  kind: IngestionHealthCheckKind;
  severity: IngestionHealthCheckSeverity;
  message: (metadata: Record<string, unknown>) => string;
}

// Kind, severity and message describe the type of check, not one occurrence: they are never stored,
// so changing them never requires rewriting Elasticsearch.
const HEALTH_CHECK_REGISTRY: Record<string, HealthCheckDefinition> = {
  // No user id or name in the message: reading a connector only needs MODULES, its user is reserved to SETTINGS_SETACCESSES
  [HEALTH_CHECK_USER_MISSING]: {
    kind: IngestionHealthCheckKind.Configuration,
    severity: IngestionHealthCheckSeverity.Blocking,
    message: () => 'User is missing',
  },
};
// endregion

// region evaluation (pure, no I/O)
export interface IngestionHealthInput {
  userId?: string | null;
  // Connectors authenticate with their own user; feeds and syncs without one run as the system user, a supported setup
  isUserRequired: boolean;
}

export const computeIngestionHealthChecks = (input: IngestionHealthInput, isExistingUser: (userId: string) => boolean): StoredHealthCheck[] => {
  const checks: StoredHealthCheck[] = [];
  const isUserMissing = input.userId ? !isExistingUser(input.userId) : input.isUserRequired;
  if (isUserMissing) {
    checks.push({ health_check_code: HEALTH_CHECK_USER_MISSING, health_check_metadata: {} });
  }
  return checks;
};

// Priority: critical > degraded > healthy. stopped comes with the checks able to prove it.
// Unknown is not a status: it is the absence of ingestion_health, before the first evaluation.
export const computeHealthStatus = (checks: StoredHealthCheck[]): IngestionHealthStatus => {
  const blockingDefinitions = checks
    .map((check) => HEALTH_CHECK_REGISTRY[check.health_check_code])
    .filter((definition) => definition?.severity === IngestionHealthCheckSeverity.Blocking);
  if (blockingDefinitions.some((definition) => definition.kind === IngestionHealthCheckKind.Runtime)) {
    return IngestionHealthStatus.Critical;
  }
  if (blockingDefinitions.some((definition) => definition.kind === IngestionHealthCheckKind.Configuration)) {
    return IngestionHealthStatus.Degraded;
  }
  return IngestionHealthStatus.Healthy;
};

const normalizeHealthChecks = (checks: StoredHealthCheck[]): StoredHealthCheck[] => {
  const normalized = checks.map((check) => ({ health_check_code: check.health_check_code, health_check_metadata: check.health_check_metadata ?? {} }));
  return normalized.sort((a, b) => a.health_check_code.localeCompare(b.health_check_code));
};

// Returns the fields to write, or null when neither the status nor the checks changed.
// The write replaces the whole ingestion_health object, so it carries the unchanged since.
export const computeIngestionHealthPatch = (current: IngestionHealthFields, checks: StoredHealthCheck[], evaluatedAt: string): IngestionHealthFields | null => {
  const currentHealth = current.ingestion_health;
  const status = computeHealthStatus(checks);
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

// Spread into the resolvers of every type carrying an ingestion health.
// Read from Elasticsearch only, never from Redis: the lists of ingestions are polled.
// Null until the manager first evaluates the ingestion, which reads as unknown.
export const toGraphqlIngestionHealth = (health: StoredIngestionHealth | undefined): IngestionHealth | null => {
  if (!health) {
    return null;
  }
  return {
    status: health.status,
    status_since: health.status_since,
    healthChecks: toGraphqlHealthChecks(health.health_checks),
  };
};

export const ingestionHealthFieldResolvers = {
  ingestionHealth: (element: IngestionHealthFields) => toGraphqlIngestionHealth(element.ingestion_health),
};
// endregion
