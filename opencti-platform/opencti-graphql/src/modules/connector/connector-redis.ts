import { getClientBase } from '../../database/redis';
import { getRuntimeData, getRuntimeDataMany, removeRuntimeData, setRuntimeData } from '../ingestionHealth/ingestionHealthRuntimeData';

export interface ConnectorHealthMetrics {
  restart_count: number;
  started_at: string;
  last_update: string;
  is_in_reboot_loop: boolean;
}

export const redisSetConnectorLogs = async (connectorId: string, logs: string[]) => {
  await getClientBase().set(`connector-${connectorId}-logs`, JSON.stringify(logs));
};

export const redisGetConnectorLogs = async (connectorId: string): Promise<string[]> => {
  const rawLogs = await getClientBase().get(`connector-${connectorId}-logs`);
  return rawLogs ? JSON.parse(rawLogs) : [];
};

export const redisSetConnectorHealthMetrics = async (connectorId: string, metrics: ConnectorHealthMetrics) => {
  await getClientBase().set(`connector-${connectorId}-health`, JSON.stringify(metrics), 'EX', 300);
};

export const redisGetConnectorHealthMetrics = async (connectorId: string): Promise<ConnectorHealthMetrics | null> => {
  const rawMetrics = await getClientBase().get(`connector-${connectorId}-health`);
  return rawMetrics ? JSON.parse(rawMetrics) : null;
};

const MANAGED_CONNECTOR_AUTO_UPGRADE_STATUS_KEY = 'managed_connector_auto_upgrade_status';

export type ManagedConnectorAutoUpgradeStatus = {
  status: 'running' | 'ready' | 'failed';
  platformVersion: string;
  startedAt: number;
  completedAt?: number;
  error?: string;
};

export const redisGetManagedConnectorAutoUpgradeStatus = async (): Promise<ManagedConnectorAutoUpgradeStatus | null> => {
  const rawStatus = await getClientBase().get(MANAGED_CONNECTOR_AUTO_UPGRADE_STATUS_KEY);
  if (!rawStatus) {
    return null;
  }
  try {
    return JSON.parse(rawStatus) as ManagedConnectorAutoUpgradeStatus;
  } catch {
    return null;
  }
};

export const redisSetManagedConnectorAutoUpgradeStatus = async (status: ManagedConnectorAutoUpgradeStatus) => {
  await getClientBase().set(MANAGED_CONNECTOR_AUTO_UPGRADE_STATUS_KEY, JSON.stringify(status));
};

// region connector heartbeats
// Connector liveness is kept out of Elasticsearch so that no entity write (migration, auto-upgrade, edition...)
// can make a connector look alive: only a connector ping or registration records a heartbeat.
// The heartbeat is a runtime data of the ingestion health, its storage (a single sorted set) is declared
// in ingestionHealthRuntimeData. It is the last heartbeat as recorded, the connector is not judged alive or not here.
export const redisSetConnectorHeartbeat = async (connectorId: string, lastSeenAt: string) => {
  await setRuntimeData(connectorId, 'heartbeat', lastSeenAt);
};

export const redisGetConnectorHeartbeat = async (connectorId: string): Promise<string | null> => {
  return (await getRuntimeData(connectorId, ['heartbeat'])).heartbeat ?? null;
};

// Connectors without heartbeat are omitted
export const redisGetConnectorsHeartbeats = async (connectorIds: string[]): Promise<Map<string, string>> => {
  const heartbeats = new Map<string, string>();
  (await getRuntimeDataMany(connectorIds, ['heartbeat'])).forEach(({ heartbeat }, connectorId) => {
    if (heartbeat) {
      heartbeats.set(connectorId, heartbeat);
    }
  });
  return heartbeats;
};

export const redisDeleteConnectorHeartbeat = async (connectorId: string) => {
  await removeRuntimeData(connectorId, 'heartbeat');
};
// endregion
