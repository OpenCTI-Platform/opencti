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

export type Config = {
  key: string,
  enabled: boolean,
  running: boolean,
};

const initClusterManager = () => {
  let scheduler: SetIntervalAsyncTimer<[]>;
  let configSubscription = {};
  let configRule = {};
  let configHistory = {};
  let configTask = {};
  let configExpiration = {};
  let configSync = {};
  let configRetention = {};

  const clusterHandler = async (platform_id: string) => {
    try {
      // receive information from the managers every 30s
      configSubscription = await subscriptionManager.status();
      configRule = await ruleEngine.status();
      configHistory = await historyManager.status();
      configTask = await taskManager.status();
      configExpiration = await expiredManager.status();
      configSync = await syncManager.status();
      configRetention = await retentionManager.status();
    } finally {
      const config_managers = [
        configSubscription,
        configRule,
        configHistory,
        configTask,
        configExpiration,
        configSync,
        configRetention,
      ];
      const config_data = {
        platform_id,
        managers: config_managers,
      };
      await registerClusterInstance(platform_id, config_data);
    }
  };

  return {
    start: async () => {
      logApp.info('[OPENCTI-MODULE] Starting cluster manager');
      const platform_id = `platform:instance:${process.pid}`;
      scheduler = setIntervalAsync(async () => {
        await clusterHandler(platform_id);
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
