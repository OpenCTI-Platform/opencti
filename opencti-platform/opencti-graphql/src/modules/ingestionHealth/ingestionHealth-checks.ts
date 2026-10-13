import * as R from 'ramda';
import { type IngestionHealthCheck, IngestionHealthCheckKind, IngestionHealthCheckSeverity, IngestionHealthStatus } from '../../generated/graphql';
import type { IngestionHealthFields, StoredHealthCheck } from './ingestionHealth-types';

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
export interface ConnectorHealthInput {
  connector_user_id?: string | null;
}

export const computeConnectorHealthChecks = (connector: ConnectorHealthInput, isExistingUser: (userId: string) => boolean): StoredHealthCheck[] => {
  const checks: StoredHealthCheck[] = [];
  if (!connector.connector_user_id || !isExistingUser(connector.connector_user_id)) {
    checks.push({ health_check_code: HEALTH_CHECK_USER_MISSING, health_check_metadata: {} });
  }
  return checks;
};

// Priority: critical > degraded > unknown. stopped and healthy come with the checks able to prove them.
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
  return IngestionHealthStatus.Unknown;
};

const normalizeHealthChecks = (checks: StoredHealthCheck[]): StoredHealthCheck[] => {
  const normalized = checks.map((check) => ({ health_check_code: check.health_check_code, health_check_metadata: check.health_check_metadata ?? {} }));
  return R.sortBy((check) => check.health_check_code, normalized);
};

// Returns the fields to write, or null when neither the status nor the checks changed
export const computeIngestionHealthPatch = (current: IngestionHealthFields, checks: StoredHealthCheck[], evaluatedAt: string): IngestionHealthFields | null => {
  const status = computeHealthStatus(checks);
  const nextChecks = normalizeHealthChecks(checks);
  const isStatusChanged = current.health_status !== status;
  const isChecksChanged = !R.equals(normalizeHealthChecks(current.health_checks ?? []), nextChecks);
  if (!isStatusChanged && !isChecksChanged) {
    return null;
  }
  const patch: IngestionHealthFields = { health_status: status, health_checks: nextChecks };
  if (isStatusChanged) {
    patch.health_status_since = evaluatedAt;
  }
  return patch;
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
// endregion
