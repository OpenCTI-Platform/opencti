import { clearIntervalAsync, setIntervalAsync, type SetIntervalAsyncTimer } from 'set-interval-async/fixed';
import { ENABLED_API, logApp, PLATFORM_INSTANCE_ID } from '../config/conf';
import historyManager from './historyManager';
import ruleEngine from './ruleManager';
import taskManager from './taskManager';
import expiredManager from './expiredManager';
import syncManager from './syncManager';
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
import playbookManager from './playbookManager/playbookManager';
import { getAllManagersStatuses } from './managerModule';
import type { ClusterConfig } from '../types/clusterConfig';

const SCHEDULE_TIME = 30000;

const initClusterManager = () => {
  let scheduler: SetIntervalAsyncTimer<[]>;
  let startingScheduler: SetIntervalAsyncTimer<[]> | undefined;
  const stopStartingScheduler = async () => {
    if (startingScheduler) {
      await clearIntervalAsync(startingScheduler);
      startingScheduler = undefined;
    }
  };
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
      publisherManager.status(),
      notificationManager.status(),
      ingestionManager.status(),
      activityManager.status(settings),
      playbookManager.status(settings),
      fileIndexManager.status(settings),
      ...getAllManagersStatuses(settings),
    ];
    const configData: ClusterConfig = { platform_id: platformId, api_enabled: ENABLED_API, managers };
    await registerClusterInstance(platformId, configData);
  };
  return {
    // A starting node serves its API before its managers are started: it is listed right away, with no managers yet,
    // so that the other nodes take it into account (logout when the last tab is closed counts the nodes serving the API).
    // The entry is renewed until the first run of the cluster manager replaces it, however long the managers take to start.
    registerStartingNode: async () => {
      const configData: ClusterConfig = { platform_id: PLATFORM_INSTANCE_ID, api_enabled: ENABLED_API, managers: [] };
      await registerClusterInstance(PLATFORM_INSTANCE_ID, configData);
      startingScheduler = setIntervalAsync(async () => {
        await registerClusterInstance(PLATFORM_INSTANCE_ID, configData);
      }, SCHEDULE_TIME);
    },
    start: async () => {
      logApp.info('[OPENCTI-MODULE] Starting cluster manager');
      await stopStartingScheduler();
      await clusterHandler(PLATFORM_INSTANCE_ID);
      // receive information from the managers every 30s
      scheduler = setIntervalAsync(async () => {
        await clusterHandler(PLATFORM_INSTANCE_ID);
      }, SCHEDULE_TIME);
    },
    shutdown: async () => {
      const startTime = Date.now();
      logApp.info('[OPENCTI-MODULE] Stopping cluster manager');
      await stopStartingScheduler();
      if (scheduler) {
        await clearIntervalAsync(scheduler);
      }
      logApp.info(`[OPENCTI-MODULE] Cluster manager stopped in ${new Date().getTime() - startTime} ms`);
      return true;
    },
  };
};

const clusterManager = initClusterManager();

export default clusterManager;
