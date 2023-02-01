import conf, {
  ENABLED_API,
  ENABLED_CONNECTOR_MANAGER,
  ENABLED_EXPIRED_MANAGER,
  ENABLED_HISTORY_MANAGER,
  ENABLED_RETENTION_MANAGER,
  ENABLED_RULE_ENGINE,
  ENABLED_SYNC_MANAGER,
  ENABLED_TASK_SCHEDULER,
  getStoppingState,
  logApp,
  setStoppingState
} from './config/conf';
import platformInit, { checkSystemDependencies } from './initialization';
import cacheManager from './manager/cacheManager';
import { initializeRedisClients, shutdownRedisClients } from './database/redis';
import httpServer from './http/httpServer';
import expiredManager from './manager/expiredManager';
import connectorManager from './manager/connectorManager';
import retentionManager from './manager/retentionManager';
import taskManager from './manager/taskManager';
import ruleEngine from './manager/ruleManager';
import syncManager from './manager/syncManager';
import historyManager from './manager/historyManager';
import clusterManager from './manager/clusterManager';

// region static graphql modules
import './modules/index';
// endregion

// region dynamic modules
const startModules = async () => {
  // region API initialization
  if (ENABLED_API) {
    await httpServer.start();
    logApp.info(`[OPENCTI] API ready on port ${conf.get('app:port')}`);
  } else {
    logApp.info('[OPENCTI] API not started (disabled by configuration)');
  }
  // endregion
  // region Expiration manager
  if (ENABLED_EXPIRED_MANAGER) {
    await expiredManager.start();
  } else {
    logApp.info('[OPENCTI-MODULE] Expiration manager not started (disabled by configuration)');
  }
  // endregion
  // region connector manager
  if (ENABLED_CONNECTOR_MANAGER) {
    await connectorManager.start();
  } else {
    logApp.info('[OPENCTI-MODULE] Connector manager not started (disabled by configuration)');
  }
  // endregion
  // region Retention manager
  if (ENABLED_RETENTION_MANAGER) {
    await retentionManager.start();
  } else {
    logApp.info('[OPENCTI-MODULE] Retention manager not started (disabled by configuration)');
  }
  // endregion
  // region Task manager
  if (ENABLED_TASK_SCHEDULER) {
    await taskManager.start();
  } else {
    logApp.info('[OPENCTI-MODULE] Task manager not started (disabled by configuration)');
  }
  // endregion
  // region Inference engine
  if (ENABLED_RULE_ENGINE) {
    await ruleEngine.start();
  } else {
    logApp.info('[OPENCTI-MODULE] Rule engine not started (disabled by configuration)');
  }
  // endregion
  // region Sync manager
  if (ENABLED_SYNC_MANAGER) {
    await syncManager.start();
  } else {
    logApp.info('[OPENCTI-MODULE] Sync manager not started (disabled by configuration)');
  }
  // endregion
  // region History manager
  if (ENABLED_HISTORY_MANAGER) {
    await historyManager.start();
  } else {
    logApp.info('[OPENCTI-MODULE] History manager not started (disabled by configuration)');
  }
  // endregion
  // region Cluster manager
  await clusterManager.start();
  // endregion
};

const shutdownModules = async () => {
  const stoppingPromises = [];
  // region API shutdown
  if (ENABLED_API) {
    stoppingPromises.push(httpServer.shutdown());
  }
  // endregion
  // region Expiration manager
  if (ENABLED_EXPIRED_MANAGER) {
    stoppingPromises.push(expiredManager.shutdown());
  }
  // endregion
  // region Retention manager
  if (ENABLED_RETENTION_MANAGER) {
    stoppingPromises.push(retentionManager.shutdown());
  }
  // endregion
  // region Task manager
  if (ENABLED_TASK_SCHEDULER) {
    stoppingPromises.push(taskManager.shutdown());
  }
  // endregion
  // region Inference engine
  if (ENABLED_RULE_ENGINE) {
    stoppingPromises.push(ruleEngine.shutdown());
  }
  // endregion
  // region Sync manager
  if (ENABLED_SYNC_MANAGER) {
    stoppingPromises.push(syncManager.shutdown());
  }
  // endregion
  // region History manager
  if (ENABLED_HISTORY_MANAGER) {
    stoppingPromises.push(historyManager.shutdown());
  }
  // endregion
  // region Cluster manager
  stoppingPromises.push(clusterManager.shutdown());
  // endregion
  await Promise.all(stoppingPromises);
};
// endregion

export const platformStart = async () => {
  logApp.info('[OPENCTI] Starting platform');
  try {
    // Initialize the redis clients
    initializeRedisClients();
    // Init the cache manager
    await cacheManager.start();
    // Check all dependencies access
    await checkSystemDependencies();
    // Init the platform default
    await platformInit();
    // Init the modules
    await startModules();
  } catch (e) {
    logApp.error('[OPENCTI] Platform start fail', { error: e });
    process.exit(1);
  }
};

export const platformStop = async () => {
  const stopTime = new Date().getTime();
  // Shutdown the cache manager
  await cacheManager.shutdown();
  // Destroy the modules
  await shutdownModules();
  // Shutdown the redis clients
  await shutdownRedisClients();
  logApp.info(`[OPENCTI] Platform stopped ${new Date().getTime() - stopTime} ms`);
  process.exit(0);
};

['SIGTERM', 'SIGINT', 'message'].forEach((signal) => {
  process.on(signal, async (message) => {
    if (signal !== 'message' || message === 'shutdown') {
      if (getStoppingState() === false) {
        setStoppingState(true);
        logApp.info(`[OPENCTI] ${signal} signal received, stopping OpenCTI`);
        try {
          await platformStop();
        } catch (e) {
          logApp.error('[OPENCTI] OpenCTI platform stop error', { error: e });
          process.exit(1);
        }
      }
    }
  });
});
