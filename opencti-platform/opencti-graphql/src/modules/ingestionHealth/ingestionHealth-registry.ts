import * as R from 'ramda';
import { INGESTION_HEALTH_FEATURE_FLAG, isFeatureEnabled } from '../../config/conf';
import { IngestionHealthCheckKind, IngestionHealthCheckSeverity } from '../../generated/graphql';
import { ENTITY_TYPE_CONNECTOR, ENTITY_TYPE_SYNC } from '../../schema/internalObject';
import { redisGetConnectorsHeartbeats } from '../connector/connector-redis';
import { findCapabilityDescription } from '../../schema/capabilities';
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
  reportedConnectorErrorMessage,
  isHeartbeatAlive,
  isUserRequiredForIngestor,
  REQUIRED_CAPABILITY_BY_INGESTOR_TYPE,
  scrubWorkError,
  withoutReportedConnectorErrorText,
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
export const HEALTH_CHECK_USER_ACCOUNT_NOT_ACTIVE = 'USER_ACCOUNT_NOT_ACTIVE';
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
  | typeof HEALTH_CHECK_USER_ACCOUNT_NOT_ACTIVE
  | typeof HEALTH_CHECK_HEARTBEAT_MISSING
  | typeof HEALTH_CHECK_USER_NOT_SERVICE_ACCOUNT
  | typeof HEALTH_CHECK_FEED_AND_SYNC_EXECUTION_FAILED
  | typeof HEALTH_CHECK_SOURCE_ACCESS_DENIED
  | typeof HEALTH_CHECK_LAST_RUN_FAILED;

interface BaseHealthCheckDefinition {
  // Name of the check, the same for every occurrence: shown in the platform settings, translated by the front (lang/back)
  label: string;
  // Precise description of the check, when the label alone is not enough: shown next to the label in the platform settings,
  // translated by the front (lang/back).
  // Detected automatically when extracting the translations (yarn extract-translation in opencti-front), like the label:
  // script/extract-label-keyword.ts collects every single-quoted string that follows the word label and a colon, which the _label suffix matches.
  // So keep the suffix, and write the value as a single-quoted literal without apostrophe, or it is not extracted.
  // Never write that pattern in a comment either: the script would extract the comment as a key
  description_label?: string;
  // A failure of this check is dropped when the check named here also fails for the same ingestor:
  // the other one tells the cause, this one would only repeat it less precisely
  supersededBy?: HealthCheckCode;
  // Feature flag the check is still under: without it, the check is neither evaluated nor listed in the platform settings
  featureFlag?: string;
  // Computed when read, never stored: the entity type of the ingestor adapts it to the kind of ingestion
  // Absent when the failure needs nothing more than the name of the check: the label is the message.
  // A {key} placeholder is filled from metadata[key]: by the front once translated, by formatHealthCheckMessage elsewhere.
  // The label of the check is given to build the message from it, so that both can't drift apart
  message?: (checkLabel: string, metadata: HealthCheckMetadata, entityType: string) => string;
  // Leaves out of the metadata the text written by the source (the connector, the feed or the sync): an error message may quote
  // a secret (a token, a header, an echoed body) that scrubWorkError does not recognize.
  // The health of the ingestor keeps it, for the readers of the ingestor. The activity events and the notifications built from them
  // do not: they reach other readers, outside the platform too. So message() must also word the failure without it.
  // Absent when the metadata holds no such text
  messageWithoutSourceText?: (metadata: HealthCheckMetadata) => HealthCheckMetadata;
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
  // Every configuration check is advisory, even when it stops the ingestion: it degrades the health, only a blocking runtime check makes it critical
  // (see computeHealthStatus), and the severity must tell the same, as the notifications group the messages by it (see groupHealthCheckMessages)
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
    message: (checkLabel) => `${checkLabel}: "{capability_description}"`,
    // Only an existing user: a missing one is reported by USER_MISSING. Internal users (system...) are not judged
    isEnabled: (ingestor, { user }) => !!user && !user.internal && ingestor.entity_type in REQUIRED_CAPABILITY_BY_INGESTOR_TYPE,
    getFailures: (ingestor, { user }) => {
      const capability = REQUIRED_CAPABILITY_BY_INGESTOR_TYPE[ingestor.entity_type];
      if (user?.hasCapability(capability)) {
        return [];
      }
      // Its description, as shown in the roles. A capability without description is shown by its name
      return [{
        severity: IngestionHealthCheckSeverity.Advisory,
        metadata: { capability, capability_description: findCapabilityDescription(capability) ?? capability },
      }];
    },
  },
  // The platform refuses to authenticate a user whose account is not active (expired, locked, disabled...): a connector can neither register nor ping,
  // and the worker impersonating the user of a feed or a sync is refused too.
  [HEALTH_CHECK_USER_ACCOUNT_NOT_ACTIVE]: {
    kind: IngestionHealthCheckKind.Configuration,
    label: 'User account is not active',
    // Only an existing user: a missing one is reported by USER_MISSING. Internal users (system...) are always active:
    // a feed or a sync without user runs as the system user, so it is never judged
    isEnabled: (_, { user }) => !!user && !user.internal,
    getFailures: (_, { user }) => (user?.user_account_active ? [] : [{ severity: IngestionHealthCheckSeverity.Advisory }]),
  },
  // An ingestion should not depend on a person: a regular user leaving or changing rights breaks it
  [HEALTH_CHECK_USER_NOT_SERVICE_ACCOUNT]: {
    kind: IngestionHealthCheckKind.Configuration,
    label: 'User is not a service account',
    description_label: 'Not necessarily blocking but using a service account is highly recommended',
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
    message: (_, metadata, entityType) => {
      const executionFailed = entityType === ENTITY_TYPE_SYNC ? 'Sync execution failed' : 'Feed execution failed';
      return metadata.failure_description ? `${executionFailed}: {failure_description}` : executionFailed;
    },
    // Only the failing ones: nothing is read for the others
    isEnabled: (ingestor) => FEED_AND_SYNC_ENTITY_TYPES.includes(ingestor.entity_type) && ingestor.last_execution_status === 'error',
    getRuntimeData: (ingestors) => getFeedsAndSyncsLastFailureDetails(ingestors.map((ingestor) => ingestor.internal_id)),
    // When the access was denied, SOURCE_ACCESS_DENIED tells the cause: only that one is reported
    supersededBy: HEALTH_CHECK_SOURCE_ACCESS_DENIED,
    // Without an http status, the description is the error message of the execution (see describeFeedAndSyncExecutionFailure)
    messageWithoutSourceText: (metadata) => (metadata.error === undefined ? metadata : R.omit(['error', 'failure_description'], metadata)),
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
    label: 'Feed or sync source denied access',
    description_label: 'Feed or sync whose last execution was refused by the source: HTTP 401/402/403',
    message: (checkLabel) => `${checkLabel}: HTTP {http_status}`,
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
    featureFlag: INGESTION_HEALTH_FEATURE_FLAG,
    message: (checkLabel, { error }) => (error ? `${checkLabel}: {error}` : checkLabel),
    // The error is the first message of the work, written by the connector
    messageWithoutSourceText: (metadata) => R.omit(['error'], metadata),
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
    message: reportedConnectorErrorMessage,
    messageWithoutSourceText: withoutReportedConnectorErrorText,
    isEnabled: (ingestor) => ingestor.entity_type === ENTITY_TYPE_CONNECTOR,
    getRuntimeData: (ingestors) => getConnectorsReportedErrors(ingestors),
    getFailures: (errors) => getReportedConnectorErrorsFailures(errors, (criticity) => criticity < CONNECTOR_ERROR_BLOCKING_CRITICITY, IngestionHealthCheckSeverity.Advisory),
  }),
  // Each error reaching the threshold is a failure of its own: blocking
  [HEALTH_CHECK_CONNECTOR_CRITICAL_ERROR_REPORTED]: defineRuntimeCheck({
    kind: IngestionHealthCheckKind.Runtime,
    label: 'Connector reported a critical error',
    message: reportedConnectorErrorMessage,
    messageWithoutSourceText: withoutReportedConnectorErrorText,
    isEnabled: (ingestor) => ingestor.entity_type === ENTITY_TYPE_CONNECTOR,
    getRuntimeData: (ingestors) => getConnectorsReportedErrors(ingestors),
    getFailures: (errors) => getReportedConnectorErrorsFailures(errors, (criticity) => criticity >= CONNECTOR_ERROR_BLOCKING_CRITICITY, IngestionHealthCheckSeverity.Blocking),
  }),
} satisfies Record<HealthCheckCode, HealthCheckDefinition>;

export const isHealthCheckCode = (code: unknown): code is HealthCheckCode => typeof code === 'string' && Object.hasOwn(HEALTH_CHECK_REGISTRY, code);

// Whether the check exists on this platform: false while its feature flag is disabled
export const isHealthCheckAvailable = (code: HealthCheckCode): boolean => {
  const { featureFlag }: HealthCheckDefinition = HEALTH_CHECK_REGISTRY[code];
  return !featureFlag || isFeatureEnabled(featureFlag);
};

// Inferred from the registry: the type of each runtime value is the one returned by the getRuntimeData of its check
type Registry = typeof HEALTH_CHECK_REGISTRY;
type RuntimeCheckCode = { [C in HealthCheckCode]: Registry[C] extends RuntimeCheckDefinition<any> ? C : never }[HealthCheckCode];
// The runtime checks of the registry, each with the type of its value: a union when they read different types
export type RegisteredRuntimeCheck = Extract<Registry[HealthCheckCode], { kind: IngestionHealthCheckKind.Runtime }>;
// The values read by the runtime checks for one ingestion, by check code
export type RuntimeData = { [C in RuntimeCheckCode]?: Registry[C] extends RuntimeCheckDefinition<infer T> ? T : never };
