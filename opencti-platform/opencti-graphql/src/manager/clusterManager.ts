import { clearIntervalAsync, setIntervalAsync, SetIntervalAsyncTimer } from 'set-interval-async/fixed';
import { logApp } from '../config/conf';
import historyManager from './historyManager';
import ruleEngine from './ruleManager';
import subscriptionManager from './subscriptionManager';
import connectorManager from './connectorManager';
import taskManager from './taskManager';
import expiredManager from './expiredManager';
import syncManager from './syncManager';
import retentionManager from './retentionManager';

const SCHEDULE_TIME = 30000;

export type Config = {
  key: string,
  enabled: boolean,
  running: boolean,
};

const initClusterManager = () => {
  let scheduler: SetIntervalAsyncTimer<[]>;
  let config_subscription = {};
  let config_rule = {};
  let config_history = {};
  let config_connector = {};
  let config_task = {};
  let config_expiration = {};
  let config_sync = {};
  let config_retention = {};

  const clusterHandler = async () => {
    try {
      logApp.info('[OPENCTI-MODULE] hello'); // printing Hello every 30s
      config_subscription = await subscriptionManager.status();
      config_rule = await ruleEngine.status();
      config_history = await historyManager.status();
      config_connector = await connectorManager.status();
      config_task = await taskManager.status();
      config_expiration = await expiredManager.status();
      config_sync = await syncManager.status();
      config_retention = await retentionManager.status();
    } finally {
      const config_managers = [
        config_subscription,
        config_rule,
        config_history,
        config_connector,
        config_task,
        config_expiration,
        config_sync,
        config_retention,
      ];
      logApp.info('config_managers = ', config_managers);
    }
  };

  return {
    start: async () => {
      logApp.info('[OPENCTI-MODULE] Starting cluster manager');
      scheduler = setIntervalAsync(async () => {
        await clusterHandler();
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
