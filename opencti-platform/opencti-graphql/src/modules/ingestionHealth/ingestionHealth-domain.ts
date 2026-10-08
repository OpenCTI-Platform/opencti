import { getEntitiesMapFromCache } from '../../database/cache';
import { fullEntitiesList } from '../../database/middleware-loader';
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
  // Refreshed by every ping: the connector heartbeat
  updated_at?: string | Date | null;
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

// Switched off by a person: same rule as isConnectorActive (database/repository.js).
// A self-hosted connector cannot be switched off from the platform.
const isStoppedByUser = (connector: IngestionHealthConnector) => {
  if (!connector.catalog_id) {
    return false;
  }
  return connector.manager_requested_status === 'stopping'
    || connector.manager_requested_status === 'stopped'
    || connector.manager_current_status === 'stopped';
};

const toDate = (value: string | Date | null | undefined): Date | null => {
  if (!value) {
    return null;
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
};

const observeHeartbeat = (connector: IngestionHealthConnector, previous: HeartbeatObservation | null, options: ObservationOptions) => {
  return nextHeartbeatObservation(previous, toDate(connector.updated_at), options);
};

export const buildIngestionHealthInput = (connector: IngestionHealthConnector, heartbeat: HeartbeatObservation): IngestionHealthInput => ({
  running: !isStoppedByUser(connector),
  run_and_terminate: connector.connector_info?.run_and_terminate === true,
  last_seen_at: toDate(connector.updated_at),
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
  const ingestionConnectors = connectors.filter((connector) => isIngestionConnector(connector as unknown as IngestionHealthConnector));
  return Promise.all(ingestionConnectors.map(async (connector) => {
    const connectorTyped = connector as unknown as IngestionHealthConnector;
    const previousHeartbeat = await redisGetIngestionHealthObservation(connectorTyped.internal_id);
    const heartbeat = observeHeartbeat(connectorTyped, previousHeartbeat, options);
    return { connector: connectorTyped, input: buildIngestionHealthInput(connectorTyped, heartbeat), previous_heartbeat: previousHeartbeat, heartbeat };
  }));
};
