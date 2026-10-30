import { redisGetIngestionLogHistory } from '../../database/redis';
import { ENTITY_TYPE_CONNECTOR, ENTITY_TYPE_SYNC } from '../../schema/internalObject';
import { ACCOUNT_STATUS_ACTIVE } from '../../config/conf';
import type { AuthUser } from '../../types/user';
import { durationInMs, utcDate } from '../../utils/format';
import { CONNECTOR_LIVELINESS_GRACE_PERIOD_MS, type ConnectorInfoError } from '../connector/connector-types';
import { redisGetConnectorErrors } from '../connector/connector-redis';
import type { IngestionHealthCheckSeverity } from '../../generated/graphql';
import type { HealthCheckFailure, HealthCheckIngestor } from './ingestionHealth-types';
import { ENTITY_TYPE_INGESTION_CSV, ENTITY_TYPE_INGESTION_JSON, ENTITY_TYPE_INGESTION_RSS, ENTITY_TYPE_INGESTION_TAXII } from '../ingestion/ingestion-types';

// region USER_MISSING

/**
 * Whether the ingestor must have its own user: true for a connector, which authenticates with it.
 * A feed or a sync without one runs as the system user, a supported setup.
 */
export const isUserRequiredForIngestor = (ingestor: HealthCheckIngestor) => ingestor.entity_type === ENTITY_TYPE_CONNECTOR;

/**
 * The id of the user the ingestor runs as: connector_user_id for a connector, user_id for a feed or a sync.
 * Null or undefined when none is set.
 */
export const getIngestorUserId = (ingestor: HealthCheckIngestor) => {
  return ingestor.entity_type === ENTITY_TYPE_CONNECTOR ? ingestor.connector_user_id : ingestor.user_id;
};

// endregion
// region user capa

// The capability the platform requires from the user of an ingestor, by entity type: a connector registers and pings with CONNECTORAPI.
// Feeds and syncs enforce none: absent, the check does not apply
export const REQUIRED_CAPABILITY_BY_INGESTOR_TYPE: Record<string, string> = {
  [ENTITY_TYPE_CONNECTOR]: 'CONNECTORAPI',
};

// endregion
// region USER_DISABLED

/**
 * Whether the platform refuses to authenticate the user: same rule as the validation of a user at login,
 * an account status other than active, or a lock date in the past (the expiration manager only updates the status later).
 */
export const isUserDisabled = (user: Pick<AuthUser, 'account_status' | 'account_lock_after_date'>): boolean => {
  return user.account_status !== ACCOUNT_STATUS_ACTIVE
    || (!!user.account_lock_after_date && utcDate().isAfter(utcDate(user.account_lock_after_date)));
};

// endregion
// region HEARTBEAT

/**
 * Whether the heartbeat is more recent than CONNECTOR_LIVELINESS_GRACE_PERIOD_MS at evaluatedAt, the window used by isConnectorActive.
 * False when there is no heartbeat; true when it is in the future (clock skew between nodes).
 */
export const isHeartbeatAlive = (heartbeat: string | undefined, evaluatedAt: string): boolean => {
  if (!heartbeat) {
    return false;
  }
  return durationInMs(heartbeat, evaluatedAt) < CONNECTOR_LIVELINESS_GRACE_PERIOD_MS;
};

// endregion
// region Feed&Sync EXECUTION_FAILED & ACCESS DENIED

// Executed by the ingestion manager (feeds) or the sync manager (syncs), which log the outcome of each execution
export const FEED_AND_SYNC_ENTITY_TYPES = [
  ENTITY_TYPE_INGESTION_RSS,
  ENTITY_TYPE_INGESTION_CSV,
  ENTITY_TYPE_INGESTION_JSON,
  ENTITY_TYPE_INGESTION_TAXII,
  ENTITY_TYPE_SYNC,
];

// Only the statuses telling that the credentials are refused: a 429 or a 5xx says nothing about access
export const ACCESS_DENIED_HTTP_STATUSES: readonly number[] = [401, 402, 403];

// The metadata of a failed feed or sync execution, see buildIngestionErrorMeta
export interface FeedAndSyncExecutionFailure {
  http_status?: number;
  http_status_text?: string;
  error_code?: string;
  cloudflare?: string;
  error?: string;
}

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
export const getFeedsAndSyncsLastFailureDetails = async (ingestionIds: string[]): Promise<Map<string, FeedAndSyncExecutionFailure>> => {
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
export const describeFeedAndSyncExecutionFailure = ({ http_status, http_status_text, error_code, cloudflare, error }: FeedAndSyncExecutionFailure) => {
  if (http_status) {
    const status = http_status_text ? `HTTP ${http_status} ${http_status_text}` : `HTTP ${http_status}`;
    return cloudflare ? `${status} (${cloudflare})` : status;
  }
  return error_code ?? error;
};

// endregion
// region reported errors (connector and work errors)

// A connector reports its errors with a criticity (higher is worse): from this one the most critical error is blocking, below it is advisory
// ponytail: arbitrary default, tune it once real connectors report errors
export const CONNECTOR_ERROR_BLOCKING_CRITICITY = 2;

// A work error can quote the url called, with its query string or its user and password: they may hold a secret,
// and the error is shown to every reader of the connector, and written in the activity log.
// The query string of any url or path, absolute or relative (urllib3 writes "with url: /v1/feed?apikey=..."),
// up to the whitespace, quote, parenthesis or bracket ending it.
// The path is looked for behind each "?" only, and the scheme is bounded: linear on a long error, a traceback included
const URL_QUERY_STRING = /\?(?<=\/[^\s'"()[\]?]*\?)[^\s'")\]]*/g;
const URL_USERINFO = /\b([a-z][a-z\d+.-]{0,30}:\/\/)[^\s/?#@'"]+@/gi;
const MAX_WORK_ERROR_LENGTH = 200;

/**
 * Removes from an error message what may hold a secret: the user and password of any url (the scheme is kept)
 * and the query string of any url or path. Then truncates it to MAX_WORK_ERROR_LENGTH characters.
 */
export const scrubWorkError = (message: string) => message
  .replace(URL_USERINFO, '$1')
  .replace(URL_QUERY_STRING, '')
  .slice(0, MAX_WORK_ERROR_LENGTH);

/**
 * Reads the errors reported on ping by each connector (they expire 10 minutes after the last ping that sent them).
 * A connector reporting no error is omitted: one not pinging has none, which is not a failure.
 */
export const getConnectorsReportedErrors = async (ingestors: HealthCheckIngestor[]): Promise<Map<string, ConnectorInfoError[]>> => {
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
 * One failure, of the given severity, per error reported on its side of the threshold; none when there is no such error.
 * Messages are scrubbed like a work error (written by the connector, they may quote a url with a secret).
 * Only the code and the message: the metadata must stay the same while the failure lasts, the criticity only sets the side.
 */
export const getReportedConnectorErrorsFailures = (
  errors: ConnectorInfoError[] | undefined,
  isOnSide: (criticity: number) => boolean,
  severity: IngestionHealthCheckSeverity,
): HealthCheckFailure[] => {
  return (errors ?? [])
    .filter(({ criticity }) => isOnSide(criticity))
    .map(({ code, message }) => ({ severity, metadata: { error_code: code, error_message: scrubWorkError(message) } }));
};

// endregion
