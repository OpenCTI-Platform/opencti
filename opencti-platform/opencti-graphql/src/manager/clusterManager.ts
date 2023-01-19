import { clearIntervalAsync, setIntervalAsync, SetIntervalAsyncTimer } from 'set-interval-async/fixed';
import { logApp } from '../config/conf';
import historyManager from './historyManager';
import ruleEngine from './ruleManager';
import subscriptionManager from './subscriptionManager';
import taskManager from './taskManager';
import expiredManager from './expiredManager';
import syncManager from './syncManager';
import retentionManager from './retentionManager';
import { registerClusterInstance } from '../database/redis';

const SCHEDULE_TIME = 30000;

export type ClusterConfig = {
  platform_id: string;
  managers: {
    id: string,
    enable: boolean,
    running: boolean
  }[]
};

const initClusterManager = () => {
  let scheduler: SetIntervalAsyncTimer<[]>;
  const clusterHandler = async (platformId: string) => {
    const managers = [
      subscriptionManager.status(),
      ruleEngine.status(),
      historyManager.status(),
      taskManager.status(),
      expiredManager.status(),
      syncManager.status(),
      retentionManager.status(),
    ];
    const configData: ClusterConfig = { platform_id: platformId, managers };
    await registerClusterInstance(platformId, configData);
  };
  return {
    start: async () => {
      logApp.info('[OPENCTI-MODULE] Starting cluster manager');
      const platformId = `platform:instance:${process.pid}`;
      await clusterHandler(platformId);
      // receive information from the managers every 30s
      scheduler = setIntervalAsync(async () => {
        await clusterHandler(platformId);
      }, SCHEDULE_TIME);
    },
    shutdown: async () => {
      logApp.info('[OPENCTI-MODULE] Stopping cluster manager');
      if (scheduler) {
        await clearIntervalAsync(scheduler);
      }
      return true;
    },
  };
};

const clusterManager = initClusterManager();

export default clusterManager;
