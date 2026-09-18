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
