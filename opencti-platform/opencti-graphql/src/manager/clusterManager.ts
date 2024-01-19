import { clearIntervalAsync, setIntervalAsync, type SetIntervalAsyncTimer } from 'set-interval-async/fixed';
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
import ingestionManager from './ingestionManager';
import activityManager from './activityManager';
import fileIndexManager from './fileIndexManager';
import { registerClusterInstance } from '../database/redis';
import { getEntityFromCache } from '../database/cache';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import type { BasicStoreSettings } from '../types/settings';
import playbookManager from './playbookManager';
import { getAllManagersStatuses } from './managerModule';

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
    const context = executionContext('cluster_manager');
    const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
    // TODO migrate managers modules
    const managers = [
      ruleEngine.status(),
      historyManager.status(),
      taskManager.status(),
      expiredManager.status(),
      syncManager.status(),
      retentionManager.status(),
      publisherManager.status(),
      notificationManager.status(),
      ingestionManager.status(),
      activityManager.status(settings),
      playbookManager.status(settings),
      fileIndexManager.status(settings),
      ...getAllManagersStatuses(),
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
