import { getEntitiesMapFromCache } from '../../database/cache';
import { fullEntitiesList } from '../../database/middleware-loader';
import { isStopRequestedByUser } from '../../database/connector-liveness';
import { redisGetConnectorsHeartbeats } from '../../database/redis';
import { ENTITY_TYPE_CONNECTOR } from '../../schema/internalObject';
import type { BasicStoreEntity } from '../../types/store';
import type { AuthContext, AuthUser } from '../../types/user';
import { SYSTEM_USER } from '../../utils/access';
import { ENTITY_TYPE_USER } from '../user/user-types';
import { computeIngestionWarnings, isPingingRegularly, nextHeartbeatObservation, type ObservationOptions } from './ingestionHealth-checks';
import { redisGetIngestionHealthObservation } from './ingestionHealth-redis';
import type { HeartbeatObservation, IngestionActingUser, IngestionCheck, IngestionHealth, IngestionHealthInput, IngestionHealthStatus } from './ingestionHealth-types';

// Stored connector fields read by the health evaluation
export interface IngestionHealthConnector {
  internal_id: string;
  name: string;
  _index: string;
  built_in?: boolean;
  connector_type?: string;
  connector_user_id?: string | null;
  catalog_id?: string | null;
  manager_requested_status?: string | null;
  manager_current_status?: string | null;
  connector_info?: { run_and_terminate?: boolean } | null;
  // Cached health, written by the ingestion health manager on change only
  ingestion_health_status?: IngestionHealthStatus;
  ingestion_health_since?: string;
  ingestion_health_summary?: string;
  ingestion_health_checks?: string; // JSON array of IngestionCheck
}

export interface IngestionSourceSnapshot {
  connector: IngestionHealthConnector;
  input: IngestionHealthInput;
  previous_heartbeat: HeartbeatObservation | null;
  heartbeat: HeartbeatObservation;
}

// Every deployed connector, whatever its type, managed by the composer or self-hosted.
// Built-in ones are platform plumbing (draft validation, csv import, internal queues) or the technical twin of a feed:
// no process deploys them and they never ping.
export const isIngestionConnector = (connector: Pick<IngestionHealthConnector, 'built_in' | 'connector_type'>) => {
  return connector.built_in !== true && connector.connector_type !== 'internal';
};

const toDate = (value: string | Date | null | undefined): Date | null => {
  if (!value) {
    return null;
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
};

// lastPing: the connector heartbeat, read from the Redis connector heartbeats (updated_at is not moved by pings anymore)
export const buildIngestionHealthInput = (connector: IngestionHealthConnector, lastPing: Date | null, heartbeat: HeartbeatObservation): IngestionHealthInput => ({
  running: !isStopRequestedByUser(connector),
  run_and_terminate: connector.connector_info?.run_and_terminate === true,
  last_seen_at: lastPing,
  pings_regularly: isPingingRegularly(heartbeat),
});

export const buildActingUser = (connector: IngestionHealthConnector, usersById: Map<string, AuthUser>): IngestionActingUser | undefined => {
  const user = connector.connector_user_id ? usersById.get(connector.connector_user_id) : undefined;
  return user ? { service_account: user.user_service_account === true } : undefined;
};

const getUsersById = (context: AuthContext) => getEntitiesMapFromCache<AuthUser>(context, SYSTEM_USER, ENTITY_TYPE_USER);

const parseCachedChecks = (rawChecks: string | undefined): IngestionCheck[] => {
  if (!rawChecks) {
    return [];
  }
  try {
    const checks = JSON.parse(rawChecks);
    return Array.isArray(checks) ? checks : [];
  } catch {
    return [];
  }
};

// Read from the cache written by the ingestion health manager, the only evaluator (RFC 0001 §4.4).
// No Redis and no evaluation here: the deployed list polls this field every 5 seconds per open tab,
// and any GraphQL error would break the whole page.
export const resolveIngestionHealth = (connector: IngestionHealthConnector): IngestionHealth | null => {
  if (!isIngestionConnector(connector)) {
    return null;
  }
  if (!connector.ingestion_health_status) {
    // Not evaluated by the manager yet, at activation for instance: never painted red
    return { status: 'unknown', summary: 'Not evaluated yet', checks: [], since: null };
  }
  return {
    status: connector.ingestion_health_status,
    summary: connector.ingestion_health_summary ?? 'Not evaluated yet',
    checks: parseCachedChecks(connector.ingestion_health_checks),
    since: toDate(connector.ingestion_health_since),
  };
};

// Configuration warnings: a direct uncached read, never part of the health verdict (RFC 0001 §4.1)
export const resolveIngestionWarnings = async (context: AuthContext, connector: IngestionHealthConnector): Promise<IngestionCheck[] | null> => {
  if (!isIngestionConnector(connector)) {
    return null;
  }
  return computeIngestionWarnings(buildActingUser(connector, await getUsersById(context)));
};

// Every ingestion connector with its evaluation input, assembled once per manager cycle.
// options: the close-pings bound of the manager period, and whether the manager was blind since its last cycle
export const collectIngestionSources = async (context: AuthContext, options: ObservationOptions): Promise<IngestionSourceSnapshot[]> => {
  const connectors = await fullEntitiesList<BasicStoreEntity>(context, SYSTEM_USER, [ENTITY_TYPE_CONNECTOR]);
  // One Redis call per cycle, before the loop. A failure fails the collection on purpose, no fallback to an empty map:
  // the handler then does not record the cycle, and the next one is blind and keeps the regular-pinger counts
  const heartbeats = await redisGetConnectorsHeartbeats();
  const ingestionConnectors = connectors.filter((connector) => isIngestionConnector(connector as unknown as IngestionHealthConnector));
  return Promise.all(ingestionConnectors.map(async (connector) => {
    const connectorTyped = connector as unknown as IngestionHealthConnector;
    const previousHeartbeat = await redisGetIngestionHealthObservation(connectorTyped.internal_id);
    const lastPing = toDate(heartbeats.get(connectorTyped.internal_id));
    const heartbeat = nextHeartbeatObservation(previousHeartbeat, lastPing, options);
    return { connector: connectorTyped, input: buildIngestionHealthInput(connectorTyped, lastPing, heartbeat), previous_heartbeat: previousHeartbeat, heartbeat };
  }));
};
