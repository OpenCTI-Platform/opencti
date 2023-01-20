import { clearIntervalAsync, setIntervalAsync, SetIntervalAsyncTimer } from 'set-interval-async/fixed';
import { v4 as uuid } from 'uuid';
import conf, { logApp } from '../config/conf';
import historyManager from './historyManager';
import ruleEngine from './ruleManager';
import taskManager from './taskManager';
import expiredManager from './expiredManager';
import syncManager from './syncManager';
import retentionManager from './retentionManager';
import publisherManager from './publisherManager';
import notificationManager from './notificationManager';
import { registerClusterInstance } from '../database/redis';

const SCHEDULE_TIME = 30000;
const NODE_INSTANCE_ID = conf.get('app:node_identifier') || uuid();

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
      ruleEngine.status(),
      historyManager.status(),
      taskManager.status(),
      expiredManager.status(),
      syncManager.status(),
      retentionManager.status(),
      publisherManager.status(),
      notificationManager.status(),
    ];
    const configData: ClusterConfig = { platform_id: platformId, managers };
    await registerClusterInstance(platformId, configData);
  };
  return {
    start: async () => {
      logApp.info('[OPENCTI-MODULE] Starting cluster manager');
      const platformId = `platform:instance:${NODE_INSTANCE_ID}`;
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
