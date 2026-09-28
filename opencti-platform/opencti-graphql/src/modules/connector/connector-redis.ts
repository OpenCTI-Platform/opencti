import { getClientBase } from '../../database/redis';

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
