import { IngestionHealthCheckKind, IngestionHealthCheckSeverity } from '../../generated/graphql';
import { ENTITY_TYPE_CONNECTOR, ENTITY_TYPE_SYNC } from '../../schema/internalObject';
import { CONNECTOR_LIVELINESS_GRACE_PERIOD_MS } from '../connector/connector-types';
import { durationInMs } from '../../utils/format';
import { ENTITY_TYPE_INGESTION_CSV, ENTITY_TYPE_INGESTION_JSON, ENTITY_TYPE_INGESTION_RSS, ENTITY_TYPE_INGESTION_TAXII } from '../ingestion/ingestion-types';
import { redisGetConnectorErrors, redisGetConnectorsHeartbeats } from '../connector/connector-redis';
import type { ConnectorInfoError } from '../connector/connector-types';
import { redisGetIngestionLogHistory } from '../../database/redis';
import { findCapabilityDescription } from '../../database/data-initialization';
import type { AuthContext, AuthUser } from '../../types/user';
import { getConclusiveWork, getWorkFailure, loadConnectorsRuntimeState } from './ingestionHealth-connectorWorks';

export const HEALTH_CHECK_USER_MISSING = 'USER_MISSING';
export const HEALTH_CHECK_USER_MISSING_CAPABILITY = 'USER_MISSING_CAPABILITY';
export const HEALTH_CHECK_HEARTBEAT_MISSING = 'HEARTBEAT_MISSING';
export const HEALTH_CHECK_USER_NOT_SERVICE_ACCOUNT = 'USER_NOT_SERVICE_ACCOUNT';
export const HEALTH_CHECK_FEED_AND_SYNC_EXECUTION_FAILED = 'FEED_AND_SYNC_EXECUTION_FAILED';
export const HEALTH_CHECK_SOURCE_ACCESS_DENIED = 'SOURCE_ACCESS_DENIED';
export const HEALTH_CHECK_LAST_RUN_FAILED = 'LAST_RUN_FAILED';
export const HEALTH_CHECK_CONNECTOR_ERROR_REPORTED = 'CONNECTOR_ERROR_REPORTED';
export const HEALTH_CHECK_CONNECTOR_CRITICAL_ERROR_REPORTED = 'CONNECTOR_CRITICAL_ERROR_REPORTED';

// A connector reports its errors with a criticity (higher is worse): from this one the most critical error is blocking, below it is advisory
// ponytail: arbitrary default, tune it once real connectors report errors
export const CONNECTOR_ERROR_BLOCKING_CRITICITY = 2;

// Every check of the registry: adding a check adds its code here
export type HealthCheckCode = typeof HEALTH_CHECK_USER_MISSING
  | typeof HEALTH_CHECK_CONNECTOR_ERROR_REPORTED
  | typeof HEALTH_CHECK_CONNECTOR_CRITICAL_ERROR_REPORTED
  | typeof HEALTH_CHECK_USER_MISSING_CAPABILITY
  | typeof HEALTH_CHECK_HEARTBEAT_MISSING
  | typeof HEALTH_CHECK_USER_NOT_SERVICE_ACCOUNT
  | typeof HEALTH_CHECK_FEED_AND_SYNC_EXECUTION_FAILED
  | typeof HEALTH_CHECK_SOURCE_ACCESS_DENIED
  | typeof HEALTH_CHECK_LAST_RUN_FAILED;

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
  // The user of a connector
  connector_user_id?: string | null;
  // The user of a feed or a sync
  user_id?: string | null;
  // The outcome of the last execution of a feed or a sync, patched by the ingestion manager or the sync manager
  last_execution_status?: string | null;
  connector_type?: string | null;
}

// Computed once at the beginning of each period of the ingestion health manager, shared by the evaluation of every ingestion.
// Known before the runtime data is read: whether a check is enabled depends on it only, which tells what to read.
export interface GlobalIngestionHealthContext {
  // Connectors pinging continuously
  pingingConnectorsIds: Set<string>;
  // ms a status must stay unchanged before it is notified, from the platform settings (default when absent)
  notificationDelay?: number;
  // Checks disabled in the platform settings: neither read nor evaluated
  disabledHealthChecks?: HealthCheckCode[];
}

// The user an ingestor runs as, as needed by the checks
export interface HealthCheckUser {
  // Platform internal user (system...): not a user account an admin manages
  internal: boolean;
  user_service_account: boolean;
  // Same rule as the platform authorization (bypass, parent capabilities)
  hasCapability: (capability: string) => boolean;
}

// What the evaluation looks at, besides the configuration of the ingestion: whether a check applies, whether it fails, the status.
// A new check needing a new fact adds a field here, not a parameter to every function.
export interface SourceIngestionHealthContext extends GlobalIngestionHealthContext {
  // The moment of the evaluation, taken right after the runtime data is read: what is stale is judged against it
  evaluatedAt: string;
  // Values read by the runtime checks enabled for this ingestion, by check code: whether they are still fresh is judged here, not when read
  runtimeData?: RuntimeData;
  // Resolved by the manager for each ingestion: absent when no user is set or it does not exist anymore
  user?: HealthCheckUser;
}

// What describes one occurrence of a failing check, stored with it in Elasticsearch (health_check_metadata) and given back to message().
// Keep it a state, not a measure: it is compared at each period, a value changing every time (a date, a counter) rewrites the ingestion every time.
export type HealthCheckMetadata = Record<string, unknown>;

interface BaseHealthCheckDefinition {
  // Name of the check, the same for every occurrence: shown in the platform settings, translated by the front (lang/back)
  label: string;
  severity: IngestionHealthCheckSeverity;
  // A failure of this check is dropped when the check named here also fails for the same ingestor:
  // the other one tells the cause, this one would only repeat it less precisely
  supersededBy?: HealthCheckCode;
  // Computed when read, never stored: the entity type of the ingestor adapts it to the kind of ingestion
  // Absent when the failure needs nothing more than the name of the check: the label is the message.
  // A {key} placeholder is filled from metadata[key]: by the front once translated, by formatHealthCheckMessage elsewhere
  message?: (metadata: HealthCheckMetadata, entityType: string) => string;
}

// getFailure returns null when the check passes, else the metadata of each failure of the check: one failure per element.
// A check fails once in most cases (a single element), several for a check with several occurrences at once (one per error a connector reports).
// An empty list is a single failure with nothing to tell
export type HealthCheckFailures = HealthCheckMetadata[] | null;

interface ConfigurationCheckDefinition extends BaseHealthCheckDefinition {
  kind: IngestionHealthCheckKind.Configuration;
  // Whether the ingestor is evaluated for this check
  isEnabled: (ingestor: HealthCheckIngestor, context: SourceIngestionHealthContext) => boolean;
  getFailure: (ingestor: HealthCheckIngestor, context: SourceIngestionHealthContext) => HealthCheckFailures;
}

// What a getRuntimeData may read through the platform, besides Redis: as the user of the ingestion health manager
export interface RuntimeDataReadContext {
  context: AuthContext;
  user: AuthUser;
}

// A runtime check is judged from a value reported by the sources, read by its getRuntimeData.
// getRuntimeData reads the values of many ingestions at once: the ingestion health manager calls it at most once per period,
// only with the active ingestors for which isEnabled is true, and not at all when there is none. It returns the values by internal_id.
// It returns what was reported, as stored: what is stale is judged by getFailure. Absent ingestions are omitted.
// A read failure must reject, never be read as a missing value.
// The value given to getFailure is undefined when the sources reported nothing.
// Its isEnabled must be false for a stopped ingestor: nothing is read for it, a missing value would be reported as a failure.
export interface RuntimeCheckDefinition<T> extends BaseHealthCheckDefinition {
  kind: IngestionHealthCheckKind.Runtime;
  // Whether the ingestor is evaluated for this check. Called before the runtime data is read, to know what to read
  isEnabled: (ingestor: HealthCheckIngestor, context: GlobalIngestionHealthContext) => boolean;
  getRuntimeData: (ingestors: HealthCheckIngestor[], read: RuntimeDataReadContext) => Promise<Map<string, T>>;
  getFailure: (value: T | undefined, context: SourceIngestionHealthContext) => HealthCheckFailures;
}

// The type of the value is inferred from getRuntimeData, so that getFailure is checked against it
const defineRuntimeCheck = <T>(definition: RuntimeCheckDefinition<T>): RuntimeCheckDefinition<T> => definition;

export type HealthCheckDefinition = ConfigurationCheckDefinition | RuntimeCheckDefinition<any>;

// Connectors authenticate with their own user; feeds and syncs without one run as the system user, a supported setup
const isUserRequired = (ingestor: HealthCheckIngestor) => ingestor.entity_type === ENTITY_TYPE_CONNECTOR;

export const getIngestorUserId = (ingestor: HealthCheckIngestor) => {
  return ingestor.entity_type === ENTITY_TYPE_CONNECTOR ? ingestor.connector_user_id : ingestor.user_id;
};

// The capability the platform requires from the user of an ingestor, by entity type: a connector registers and pings with CONNECTORAPI.
// Feeds and syncs enforce none: absent, the check does not apply
const REQUIRED_CAPABILITY_BY_ENTITY_TYPE: Record<string, string> = {
  [ENTITY_TYPE_CONNECTOR]: 'CONNECTORAPI',
};

// Executed by the ingestion manager (feeds) or the sync manager (syncs), which log the outcome of each execution
const FEED_AND_SYNC_ENTITY_TYPES = [ENTITY_TYPE_INGESTION_RSS, ENTITY_TYPE_INGESTION_CSV, ENTITY_TYPE_INGESTION_JSON, ENTITY_TYPE_INGESTION_TAXII, ENTITY_TYPE_SYNC];

// The metadata of a failed feed or sync execution, see buildIngestionErrorMeta
interface FeedAndSyncExecutionFailure {
  http_status?: number;
  http_status_text?: string;
  error_code?: string;
  cloudflare?: string;
  error?: string;
}

// Only the statuses telling that the credentials are refused: a 429 or a 5xx says nothing about access
const ACCESS_DENIED_HTTP_STATUSES: readonly number[] = [401, 402, 403];

/**
 * Reads the details of the last failed execution of each feed or sync, from its ingestion logs.
 * The logs also hold the progress of an execution (started, buffering...): the last outcome is the most recent success or error,
 * and only a failure has details.
 *
 * Details only: that the execution failed is known from the feed or sync itself (last_execution_status).
 * They may be missing, the logs being bounded: the failure is then reported without them.
 *
 * @param ingestionIds the feeds and syncs to read
 * @returns the metadata of the failure by ingestion id, ingestions whose last outcome logged is not a failure are omitted
 */
const getFeedsAndSyncsLastFailureDetails = async (ingestionIds: string[]): Promise<Map<string, FeedAndSyncExecutionFailure>> => {
  const histories = await Promise.all(ingestionIds.map((ingestionId) => redisGetIngestionLogHistory(ingestionId)));
  const details = new Map<string, FeedAndSyncExecutionFailure>();
  histories.forEach((history, index) => {
    // Most recent first
    const lastOutcome = history.find((entry) => entry.level === 'success' || entry.level === 'error');
    if (lastOutcome?.level === 'error') {
      details.set(ingestionIds[index], { ...lastOutcome.meta });
    }
  });
  return details;
};

/**
 * Short description of a failed feed or sync execution, from its ingestion log metadata.
 * The HTTP status (with Cloudflare detail when present) when the source answered, else the error code or raw error.
 * Undefined when the metadata carries none of them.
 */
const describeFeedAndSyncExecutionFailure = ({ http_status, http_status_text, error_code, cloudflare, error }: FeedAndSyncExecutionFailure) => {
  if (http_status) {
    const status = http_status_text ? `HTTP ${http_status} ${http_status_text}` : `HTTP ${http_status}`;
    return cloudflare ? `${status} (${cloudflare})` : status;
  }
  return error_code ?? error;
};

// A work error can quote the url called, with its query string or its user and password: they may hold a secret,
// and the error is shown to every reader of the connector, and written in the activity log.
// The query string of any url or path, absolute or relative (urllib3 writes "with url: /v1/feed?apikey=..."),
// up to the whitespace, quote, parenthesis or bracket ending it.
// The path is looked for behind each "?" only, and the scheme is bounded: linear on a long error, a traceback included
const URL_QUERY_STRING = /\?(?<=\/[^\s'"()[\]?]*\?)[^\s'")\]]*/g;
const URL_USERINFO = /\b([a-z][a-z\d+.-]{0,30}:\/\/)[^\s/?#@'"]+@/gi;
const MAX_WORK_ERROR_LENGTH = 200;

const scrubWorkError = (message: string) => message
  .replace(URL_USERINFO, '$1')
  .replace(URL_QUERY_STRING, '')
  .slice(0, MAX_WORK_ERROR_LENGTH);

/**
 * Reads the errors reported on ping by each connector (they expire 10 minutes after the last ping that sent them).
 * A connector reporting no error is omitted: one not pinging has none, which is not a failure.
 */
const getConnectorsReportedErrors = async (ingestors: HealthCheckIngestor[]): Promise<Map<string, ConnectorInfoError[]>> => {
  const errorsByConnector = await Promise.all(ingestors.map((ingestor) => redisGetConnectorErrors(ingestor.internal_id)));
  const reportedErrors = new Map<string, ConnectorInfoError[]>();
  errorsByConnector.forEach((errors, index) => {
    if (errors.length > 0) {
      reportedErrors.set(ingestors[index].internal_id, errors);
    }
  });
  return reportedErrors;
};

/**
 * One failure per error reported on its side of the threshold, null when there is no such error.
 * Messages are scrubbed like a work error (written by the connector, they may quote a url with a secret).
 * Only the code and the message: the metadata must stay the same while the failure lasts, the criticity only sets the side.
 */
const getReportedErrorsFailures = (errors: ConnectorInfoError[] | undefined, isOnSide: (criticity: number) => boolean): HealthCheckFailures => {
  const failures = (errors ?? [])
    .filter(({ criticity }) => isOnSide(criticity))
    .map(({ code, message }) => ({ error_code: code, error_message: scrubWorkError(message) }));
  return failures.length > 0 ? failures : null;
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
  // No user id or name in the message: reading a connector only needs MODULES, its user is reserved to SETTINGS_SETACCESSES.
  // Advisory: a configuration check degrades the health, only a blocking runtime check makes it critical (see computeHealthStatus)
  [HEALTH_CHECK_USER_MISSING]: {
    kind: IngestionHealthCheckKind.Configuration,
    label: 'User is missing',
    severity: IngestionHealthCheckSeverity.Advisory,
    // A required user, or an optional one that was set: it must exist
    isEnabled: (ingestor) => isUserRequired(ingestor) || !!getIngestorUserId(ingestor),
    getFailure: (_, { user }) => (user ? null : []),
  },
  // Without it the platform refuses what the ingestor does (a connector cannot register nor ping)
  [HEALTH_CHECK_USER_MISSING_CAPABILITY]: {
    kind: IngestionHealthCheckKind.Configuration,
    label: 'User lacks required capability',
    severity: IngestionHealthCheckSeverity.Blocking,
    // The description of the capability, translated by the front as in the roles
    message: () => 'User lacks required capability: "{capability_description}"',
    // Only an existing user: a missing one is reported by USER_MISSING. Internal users (system...) are not judged
    isEnabled: (ingestor, { user }) => !!user && !user.internal && ingestor.entity_type in REQUIRED_CAPABILITY_BY_ENTITY_TYPE,
    getFailure: (ingestor, { user }) => {
      const capability = REQUIRED_CAPABILITY_BY_ENTITY_TYPE[ingestor.entity_type];
      if (user?.hasCapability(capability)) {
        return null;
      }
      // Its description, as shown in the roles. A capability without description is shown by its name
      return [{ capability, capability_description: findCapabilityDescription(capability) ?? capability }];
    },
  },
  // An ingestion should not depend on a person: a regular user leaving or changing rights breaks it
  [HEALTH_CHECK_USER_NOT_SERVICE_ACCOUNT]: {
    kind: IngestionHealthCheckKind.Configuration,
    label: 'User is not a service account',
    severity: IngestionHealthCheckSeverity.Advisory,
    // Only an existing user: a missing one is reported by USER_MISSING. Internal users (system...) are not judged
    isEnabled: (_, { user }) => !!user && !user.internal,
    getFailure: (_, { user }) => (user?.user_service_account ? null : []),
  },
  // A running process pings regularly: no heartbeat means it is down
  [HEALTH_CHECK_HEARTBEAT_MISSING]: defineRuntimeCheck({
    kind: IngestionHealthCheckKind.Runtime,
    label: 'No heartbeat received',
    severity: IngestionHealthCheckSeverity.Blocking,
    // Only the running connectors pinging continuously: the others would be missing their heartbeat between two runs
    isEnabled: (ingestor, { pingingConnectorsIds }) => pingingConnectorsIds.has(ingestor.internal_id),
    // The heartbeats of every connector are read at once: the ingestors are not needed
    getRuntimeData: () => redisGetConnectorsHeartbeats(),
    getFailure: (heartbeat, { evaluatedAt }) => (isHeartbeatAlive(heartbeat, evaluatedAt) ? null : []),
  }),
  // Any failure of the last execution of a feed or a sync (source unreachable, not found, unauthorized, invalid data...):
  // nothing is ingested until it succeeds again. Known from the feed or sync itself, the next success clears it
  [HEALTH_CHECK_FEED_AND_SYNC_EXECUTION_FAILED]: defineRuntimeCheck({
    kind: IngestionHealthCheckKind.Runtime,
    label: 'Feed or sync execution failed',
    severity: IngestionHealthCheckSeverity.Blocking,
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
    getFailure: (details) => {
      const failureDescription = details ? describeFeedAndSyncExecutionFailure(details) : undefined;
      return [{ ...details, ...(failureDescription ? { failure_description: failureDescription } : {}) }];
    },
  }),
  // The source refuses the credentials of the feed or the sync (HTTP 401, 402, 403): nothing is ingested until they are fixed.
  // Read from the same details as FEED_AND_SYNC_EXECUTION_FAILED
  [HEALTH_CHECK_SOURCE_ACCESS_DENIED]: defineRuntimeCheck({
    kind: IngestionHealthCheckKind.Runtime,
    label: 'Source denied access',
    severity: IngestionHealthCheckSeverity.Blocking,
    message: () => 'Source denied access: HTTP {http_status}',
    // Only the failing ones: nothing is read for the others
    isEnabled: (ingestor) => FEED_AND_SYNC_ENTITY_TYPES.includes(ingestor.entity_type) && ingestor.last_execution_status === 'error',
    getRuntimeData: (ingestors) => getFeedsAndSyncsLastFailureDetails(ingestors.map((ingestor) => ingestor.internal_id)),
    // Only the status: the metadata must stay the same while the failure lasts
    getFailure: (details) => {
      const httpStatus = details?.http_status;
      return httpStatus !== undefined && ACCESS_DENIED_HTTP_STATUSES.includes(httpStatus) ? [{ http_status: httpStatus }] : null;
    },
  }),
  // The last run of the connector ended with an error. Advisory: the connector may still ingest, and the next successful run clears it.
  // Another work of the connector may have succeeded since: only the last conclusive one is judged
  [HEALTH_CHECK_LAST_RUN_FAILED]: defineRuntimeCheck({
    kind: IngestionHealthCheckKind.Runtime,
    label: 'Last run failed',
    severity: IngestionHealthCheckSeverity.Advisory,
    message: ({ error }) => (error ? 'Last run failed: {error}' : 'Last run failed'),
    // A stream has no run. Managed or not: the work is reported by the connector itself
    isEnabled: (ingestor) => ingestor.entity_type === ENTITY_TYPE_CONNECTOR && ingestor.connector_type !== 'STREAM',
    getRuntimeData: (ingestors, read) => loadConnectorsRuntimeState(ingestors, read),
    getFailure: (state) => {
      const work = state && getConclusiveWork(state);
      // Not messages.length: errors of the connector with a source do not make a failed work
      const failure = work && getWorkFailure(work);
      if (!failure?.failed) {
        return null;
      }
      // The first message is the one of the connector. Not dated: the metadata must stay the same while the failure lasts
      const message = failure.messages[0];
      return message ? [{ error: scrubWorkError(message) }] : [];
    },
  }),
  // Errors the connector reports itself on ping. Every connector: one not pinging reported nothing, which is no failure.
  // Each error under the threshold is a failure of its own: advisory, the connector may still ingest
  [HEALTH_CHECK_CONNECTOR_ERROR_REPORTED]: defineRuntimeCheck({
    kind: IngestionHealthCheckKind.Runtime,
    label: 'Connector reported an error',
    severity: IngestionHealthCheckSeverity.Advisory,
    message: () => 'Connector reported an error: {error_code} - {error_message}',
    isEnabled: (ingestor) => ingestor.entity_type === ENTITY_TYPE_CONNECTOR,
    getRuntimeData: (ingestors) => getConnectorsReportedErrors(ingestors),
    getFailure: (errors) => getReportedErrorsFailures(errors, (criticity) => criticity < CONNECTOR_ERROR_BLOCKING_CRITICITY),
  }),
  // Each error reaching the threshold is a failure of its own: blocking
  [HEALTH_CHECK_CONNECTOR_CRITICAL_ERROR_REPORTED]: defineRuntimeCheck({
    kind: IngestionHealthCheckKind.Runtime,
    label: 'Connector reported a critical error',
    severity: IngestionHealthCheckSeverity.Blocking,
    message: () => 'Connector reported a critical error: {error_code} - {error_message}',
    isEnabled: (ingestor) => ingestor.entity_type === ENTITY_TYPE_CONNECTOR,
    getRuntimeData: (ingestors) => getConnectorsReportedErrors(ingestors),
    getFailure: (errors) => getReportedErrorsFailures(errors, (criticity) => criticity >= CONNECTOR_ERROR_BLOCKING_CRITICITY),
  }),
} satisfies Record<HealthCheckCode, HealthCheckDefinition>;

export const isHealthCheckCode = (code: unknown): code is HealthCheckCode => typeof code === 'string' && Object.hasOwn(HEALTH_CHECK_REGISTRY, code);
