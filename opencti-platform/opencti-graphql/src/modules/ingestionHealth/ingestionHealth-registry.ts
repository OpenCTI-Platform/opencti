import { IngestionHealthCheckKind, IngestionHealthCheckSeverity } from '../../generated/graphql';
import { ENTITY_TYPE_CONNECTOR, ENTITY_TYPE_SYNC } from '../../schema/internalObject';
import { redisGetConnectorsHeartbeats } from '../connector/connector-redis';
import { findCapabilityDescription } from '../../database/data-initialization';
import { getConclusiveWork, getWorkFailure, loadConnectorsRuntimeState } from './ingestionHealth-connectorWorks';
import {
  ACCESS_DENIED_HTTP_STATUSES,
  CONNECTOR_ERROR_BLOCKING_CRITICITY,
  describeFeedAndSyncExecutionFailure,
  FEED_AND_SYNC_ENTITY_TYPES,
  getConnectorsReportedErrors,
  getFeedsAndSyncsLastFailureDetails,
  getIngestorUserId,
  getReportedConnectorErrorsFailures,
  isHeartbeatAlive,
  isUserRequiredForIngestor,
  REQUIRED_CAPABILITY_BY_INGESTOR_TYPE,
  scrubWorkError,
} from './ingestionHealth-registry-utils';
import type {
  GlobalIngestionHealthContext,
  HealthCheckFailure,
  HealthCheckIngestor,
  HealthCheckMetadata,
  RuntimeDataReadContext,
  SourceIngestionHealthContext,
} from './ingestionHealth-types';

export const HEALTH_CHECK_USER_MISSING = 'USER_MISSING';
export const HEALTH_CHECK_USER_MISSING_CAPABILITY = 'USER_MISSING_CAPABILITY';
export const HEALTH_CHECK_USER_DISABLED = 'USER_DISABLED';
export const HEALTH_CHECK_HEARTBEAT_MISSING = 'HEARTBEAT_MISSING';
export const HEALTH_CHECK_USER_NOT_SERVICE_ACCOUNT = 'USER_NOT_SERVICE_ACCOUNT';
export const HEALTH_CHECK_FEED_AND_SYNC_EXECUTION_FAILED = 'FEED_AND_SYNC_EXECUTION_FAILED';
export const HEALTH_CHECK_SOURCE_ACCESS_DENIED = 'SOURCE_ACCESS_DENIED';
export const HEALTH_CHECK_LAST_RUN_FAILED = 'LAST_RUN_FAILED';
export const HEALTH_CHECK_CONNECTOR_ERROR_REPORTED = 'CONNECTOR_ERROR_REPORTED';
export const HEALTH_CHECK_CONNECTOR_CRITICAL_ERROR_REPORTED = 'CONNECTOR_CRITICAL_ERROR_REPORTED';

// Every check of the registry: adding a check adds its code here
export type HealthCheckCode = typeof HEALTH_CHECK_USER_MISSING
  | typeof HEALTH_CHECK_CONNECTOR_ERROR_REPORTED
  | typeof HEALTH_CHECK_CONNECTOR_CRITICAL_ERROR_REPORTED
  | typeof HEALTH_CHECK_USER_MISSING_CAPABILITY
  | typeof HEALTH_CHECK_USER_DISABLED
  | typeof HEALTH_CHECK_HEARTBEAT_MISSING
  | typeof HEALTH_CHECK_USER_NOT_SERVICE_ACCOUNT
  | typeof HEALTH_CHECK_FEED_AND_SYNC_EXECUTION_FAILED
  | typeof HEALTH_CHECK_SOURCE_ACCESS_DENIED
  | typeof HEALTH_CHECK_LAST_RUN_FAILED;

interface BaseHealthCheckDefinition {
  // Name of the check, the same for every occurrence: shown in the platform settings, translated by the front (lang/back)
  label: string;
  // A failure of this check is dropped when the check named here also fails for the same ingestor:
  // the other one tells the cause, this one would only repeat it less precisely
  supersededBy?: HealthCheckCode;
  // Computed when read, never stored: the entity type of the ingestor adapts it to the kind of ingestion
  // Absent when the failure needs nothing more than the name of the check: the label is the message.
  // A {key} placeholder is filled from metadata[key]: by the front once translated, by formatHealthCheckMessage elsewhere
  message?: (metadata: HealthCheckMetadata, entityType: string) => string;
}

// A runtime check is judged from a value reported by the sources, read by its getRuntimeData.
// getRuntimeData reads the values of many ingestions at once: the ingestion health manager calls it at most once per period,
// only with the active ingestors for which isEnabled is true, and not at all when there is none. It returns the values by internal_id.
// It returns what was reported, as stored: what is stale is judged by getFailures. Absent ingestions are omitted.
// A read failure must reject, never be read as a missing value.
// The value given to getFailures is undefined when the sources reported nothing.
// Its isEnabled must be false for a stopped ingestor: nothing is read for it, a missing value would be reported as a failure.
interface RuntimeCheckDefinition<T> extends BaseHealthCheckDefinition {
  kind: IngestionHealthCheckKind.Runtime;
  // Whether the ingestor is evaluated for this check. Called before the runtime data is read, to know what to read
  isEnabled: (ingestor: HealthCheckIngestor, context: GlobalIngestionHealthContext) => boolean;
  getRuntimeData: (ingestors: HealthCheckIngestor[], read: RuntimeDataReadContext) => Promise<Map<string, T>>;
  getFailures: (value: T | undefined, context: SourceIngestionHealthContext) => HealthCheckFailure[];
}

interface ConfigurationCheckDefinition extends BaseHealthCheckDefinition {
  kind: IngestionHealthCheckKind.Configuration;
  // Whether the ingestor is evaluated for this check
  isEnabled: (ingestor: HealthCheckIngestor, context: SourceIngestionHealthContext) => boolean;
  getFailures: (ingestor: HealthCheckIngestor, context: SourceIngestionHealthContext) => HealthCheckFailure[];
}

/**
 * Returns the definition as is. Only typing: T is inferred from getRuntimeData, so that getFailures is checked against it.
 * Without it, a check in the HealthCheckDefinition list is a RuntimeCheckDefinition<any>, and getFailures takes any value.
 */
const defineRuntimeCheck = <T>(definition: RuntimeCheckDefinition<T>): RuntimeCheckDefinition<T> => definition;

export type HealthCheckDefinition = ConfigurationCheckDefinition | RuntimeCheckDefinition<any>;

// Kind, label and message describe the type of check, not one occurrence: they are never stored,
// so changing them never requires rewriting Elasticsearch. The severity is not part of it: each failure returned by getFailures carries its own.
// Not annotated but checked with satisfies: the annotation would widen every check to HealthCheckDefinition,
// losing the type of the runtime values that RuntimeData is inferred from
export const HEALTH_CHECK_REGISTRY = {
  // No user id or name in the message: reading a connector only needs MODULES, its user is reserved to SETTINGS_SETACCESSES.
  // Advisory: a configuration check degrades the health, only a blocking runtime check makes it critical (see computeHealthStatus)
  [HEALTH_CHECK_USER_MISSING]: {
    kind: IngestionHealthCheckKind.Configuration,
    label: 'User is missing',
    // A required user, or an optional one that was set: it must exist
    isEnabled: (ingestor) => isUserRequiredForIngestor(ingestor) || !!getIngestorUserId(ingestor),
    getFailures: (_, { user }) => (user ? [] : [{ severity: IngestionHealthCheckSeverity.Advisory }]),
  },
  // Without it the platform refuses what the ingestor does (a connector cannot register nor ping)
  [HEALTH_CHECK_USER_MISSING_CAPABILITY]: {
    kind: IngestionHealthCheckKind.Configuration,
    label: 'User lacks required capability',
    // The description of the capability, translated by the front as in the roles
    message: () => 'User lacks required capability: "{capability_description}"',
    // Only an existing user: a missing one is reported by USER_MISSING. Internal users (system...) are not judged
    isEnabled: (ingestor, { user }) => !!user && !user.internal && ingestor.entity_type in REQUIRED_CAPABILITY_BY_INGESTOR_TYPE,
    getFailures: (ingestor, { user }) => {
      const capability = REQUIRED_CAPABILITY_BY_INGESTOR_TYPE[ingestor.entity_type];
      if (user?.hasCapability(capability)) {
        return [];
      }
      // Its description, as shown in the roles. A capability without description is shown by its name
      return [{
        severity: IngestionHealthCheckSeverity.Blocking,
        metadata: { capability, capability_description: findCapabilityDescription(capability) ?? capability },
      }];
    },
  },
  // The platform refuses to authenticate a disabled user (locked, expired...): a connector can neither register nor ping,
  // and the worker impersonating the user of a feed or a sync is refused too.
  [HEALTH_CHECK_USER_DISABLED]: {
    kind: IngestionHealthCheckKind.Configuration,
    label: 'User is disabled',
    // Only an existing user: a missing one is reported by USER_MISSING. Internal users (system...) are never disabled:
    // a feed or a sync without user runs as the system user, so it is never judged
    isEnabled: (_, { user }) => !!user && !user.internal,
    getFailures: (_, { user }) => (user?.disabled ? [{ severity: IngestionHealthCheckSeverity.Blocking }] : []),
  },
  // An ingestion should not depend on a person: a regular user leaving or changing rights breaks it
  [HEALTH_CHECK_USER_NOT_SERVICE_ACCOUNT]: {
    kind: IngestionHealthCheckKind.Configuration,
    label: 'User is not a service account',
    // Only an existing user: a missing one is reported by USER_MISSING. Internal users (system...) are not judged
    isEnabled: (_, { user }) => !!user && !user.internal,
    getFailures: (_, { user }) => (user?.user_service_account ? [] : [{ severity: IngestionHealthCheckSeverity.Advisory }]),
  },
  // A running process pings regularly: no heartbeat means it is down
  [HEALTH_CHECK_HEARTBEAT_MISSING]: defineRuntimeCheck({
    kind: IngestionHealthCheckKind.Runtime,
    label: 'No heartbeat received',
    // Only the running connectors pinging continuously: the others would be missing their heartbeat between two runs
    isEnabled: (ingestor, { pingingConnectorsIds }) => pingingConnectorsIds.has(ingestor.internal_id),
    // The heartbeats of every connector are read at once: the ingestors are not needed
    getRuntimeData: () => redisGetConnectorsHeartbeats(),
    getFailures: (heartbeat, { evaluatedAt }) => (isHeartbeatAlive(heartbeat, evaluatedAt) ? [] : [{ severity: IngestionHealthCheckSeverity.Blocking }]),
  }),
  // Any failure of the last execution of a feed or a sync (source unreachable, not found, unauthorized, invalid data...):
  // nothing is ingested until it succeeds again. Known from the feed or sync itself, the next success clears it
  [HEALTH_CHECK_FEED_AND_SYNC_EXECUTION_FAILED]: defineRuntimeCheck({
    kind: IngestionHealthCheckKind.Runtime,
    label: 'Feed or sync execution failed',
    // The details stay out of the text: the front translates the message before filling {failure_description}
    message: (metadata, entityType) => {
      const executionFailed = entityType === ENTITY_TYPE_SYNC ? 'Sync execution failed' : 'Feed execution failed';
      return metadata.failure_description ? `${executionFailed}: {failure_description}` : executionFailed;
    },
    // Only the failing ones: nothing is read for the others
    isEnabled: (ingestor) => FEED_AND_SYNC_ENTITY_TYPES.includes(ingestor.entity_type) && ingestor.last_execution_status === 'error',
    getRuntimeData: (ingestors) => getFeedsAndSyncsLastFailureDetails(ingestors.map((ingestor) => ingestor.internal_id)),
    // When the access was denied, SOURCE_ACCESS_DENIED tells the cause: only that one is reported
    supersededBy: HEALTH_CHECK_SOURCE_ACCESS_DENIED,
    // The details are not always known: the failure is reported without them. They are not dated: the metadata must stay the same while the failure lasts.
    // Their description fills the message: stored with them, it is the same for the same details
    getFailures: (details) => {
      const failureDescription = details ? describeFeedAndSyncExecutionFailure(details) : undefined;
      return [{
        severity: IngestionHealthCheckSeverity.Blocking,
        metadata: { ...details, ...(failureDescription ? { failure_description: failureDescription } : {}) },
      }];
    },
  }),
  // The source refuses the credentials of the feed or the sync (HTTP 401, 402, 403): nothing is ingested until they are fixed.
  // Read from the same details as FEED_AND_SYNC_EXECUTION_FAILED
  [HEALTH_CHECK_SOURCE_ACCESS_DENIED]: defineRuntimeCheck({
    kind: IngestionHealthCheckKind.Runtime,
    label: 'Source denied access',
    message: () => 'Source denied access: HTTP {http_status}',
    // Only the failing ones: nothing is read for the others
    isEnabled: (ingestor) => FEED_AND_SYNC_ENTITY_TYPES.includes(ingestor.entity_type) && ingestor.last_execution_status === 'error',
    getRuntimeData: (ingestors) => getFeedsAndSyncsLastFailureDetails(ingestors.map((ingestor) => ingestor.internal_id)),
    // Only the status: the metadata must stay the same while the failure lasts
    getFailures: (details) => {
      const httpStatus = details?.http_status;
      return httpStatus !== undefined && ACCESS_DENIED_HTTP_STATUSES.includes(httpStatus)
        ? [{ severity: IngestionHealthCheckSeverity.Blocking, metadata: { http_status: httpStatus } }]
        : [];
    },
  }),
  // The last run of the connector ended with an error. Advisory: the connector may still ingest, and the next successful run clears it.
  // Another work of the connector may have succeeded since: only the last conclusive one is judged
  [HEALTH_CHECK_LAST_RUN_FAILED]: defineRuntimeCheck({
    kind: IngestionHealthCheckKind.Runtime,
    label: 'Last run failed',
    message: ({ error }) => (error ? 'Last run failed: {error}' : 'Last run failed'),
    // A stream has no run. Managed or not: the work is reported by the connector itself
    isEnabled: (ingestor) => ingestor.entity_type === ENTITY_TYPE_CONNECTOR && ingestor.connector_type !== 'STREAM',
    getRuntimeData: (ingestors, read) => loadConnectorsRuntimeState(ingestors, read),
    getFailures: (state) => {
      const work = state && getConclusiveWork(state);
      // Not messages.length: errors of the connector with a source do not make a failed work
      const failure = work && getWorkFailure(work);
      if (!failure?.failed) {
        return [];
      }
      // The first message is the one of the connector. Not dated: the metadata must stay the same while the failure lasts
      const message = failure.messages[0];
      return [{
        severity: IngestionHealthCheckSeverity.Advisory,
        ...(message ? { metadata: { error: scrubWorkError(message) } } : {}),
      }];
    },
  }),
  // Errors the connector reports itself on ping. Every connector: one not pinging reported nothing, which is no failure.
  // Each error under the threshold is a failure of its own: advisory, the connector may still ingest
  [HEALTH_CHECK_CONNECTOR_ERROR_REPORTED]: defineRuntimeCheck({
    kind: IngestionHealthCheckKind.Runtime,
    label: 'Connector reported an error',
    message: () => 'Connector reported an error: {error_code} - {error_message}',
    isEnabled: (ingestor) => ingestor.entity_type === ENTITY_TYPE_CONNECTOR,
    getRuntimeData: (ingestors) => getConnectorsReportedErrors(ingestors),
    getFailures: (errors) => getReportedConnectorErrorsFailures(errors, (criticity) => criticity < CONNECTOR_ERROR_BLOCKING_CRITICITY, IngestionHealthCheckSeverity.Advisory),
  }),
  // Each error reaching the threshold is a failure of its own: blocking
  [HEALTH_CHECK_CONNECTOR_CRITICAL_ERROR_REPORTED]: defineRuntimeCheck({
    kind: IngestionHealthCheckKind.Runtime,
    label: 'Connector reported a critical error',
    message: () => 'Connector reported a critical error: {error_code} - {error_message}',
    isEnabled: (ingestor) => ingestor.entity_type === ENTITY_TYPE_CONNECTOR,
    getRuntimeData: (ingestors) => getConnectorsReportedErrors(ingestors),
    getFailures: (errors) => getReportedConnectorErrorsFailures(errors, (criticity) => criticity >= CONNECTOR_ERROR_BLOCKING_CRITICITY, IngestionHealthCheckSeverity.Blocking),
  }),
} satisfies Record<HealthCheckCode, HealthCheckDefinition>;

export const isHealthCheckCode = (code: unknown): code is HealthCheckCode => typeof code === 'string' && Object.hasOwn(HEALTH_CHECK_REGISTRY, code);

// Inferred from the registry: the type of each runtime value is the one returned by the getRuntimeData of its check
type Registry = typeof HEALTH_CHECK_REGISTRY;
type RuntimeCheckCode = { [C in HealthCheckCode]: Registry[C] extends RuntimeCheckDefinition<any> ? C : never }[HealthCheckCode];
// The runtime checks of the registry, each with the type of its value: a union when they read different types
export type RegisteredRuntimeCheck = Extract<Registry[HealthCheckCode], { kind: IngestionHealthCheckKind.Runtime }>;
// The values read by the runtime checks for one ingestion, by check code
export type RuntimeData = { [C in RuntimeCheckCode]?: Registry[C] extends RuntimeCheckDefinition<infer T> ? T : never };
