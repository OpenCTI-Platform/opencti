import { getClientBase } from '../../database/redis';

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
// Single sorted set (member: connector id, score: last heartbeat epoch ms) so that listing works in one call, cluster included.
const CONNECTOR_HEARTBEATS_KEY = 'connector_heartbeats';

export const redisSetConnectorHeartbeat = async (connectorId: string, lastSeenAt: string) => {
  await getClientBase().zadd(CONNECTOR_HEARTBEATS_KEY, new Date(lastSeenAt).getTime(), connectorId);
};

export const redisGetConnectorHeartbeat = async (connectorId: string): Promise<string | null> => {
  const score = await getClientBase().zscore(CONNECTOR_HEARTBEATS_KEY, connectorId);
  return score ? new Date(Number(score)).toISOString() : null;
};

export const redisGetConnectorsHeartbeats = async (): Promise<Map<string, string>> => {
  const membersWithScores = await getClientBase().zrange(CONNECTOR_HEARTBEATS_KEY, 0, -1, 'WITHSCORES');
  const heartbeats = new Map<string, string>();
  for (let i = 0; i < membersWithScores.length; i += 2) {
    heartbeats.set(membersWithScores[i], new Date(Number(membersWithScores[i + 1])).toISOString());
  }
  return heartbeats;
};

export const redisDeleteConnectorHeartbeat = async (connectorId: string) => {
  await getClientBase().zrem(CONNECTOR_HEARTBEATS_KEY, connectorId);
};
// endregion
