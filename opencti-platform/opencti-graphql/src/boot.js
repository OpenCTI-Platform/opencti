import conf, {
  ENABLED_API,
  ENABLED_CONNECTOR_MANAGER,
  ENABLED_EXPIRED_MANAGER,
  ENABLED_FILE_INDEX_MANAGER,
  ENABLED_HISTORY_MANAGER,
  ENABLED_INGESTION_MANAGER,
  ENABLED_NOTIFICATION_MANAGER,
  ENABLED_PLAYBOOK_MANAGER,
  ENABLED_PUBLISHER_MANAGER,
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
import { shutdownRedisClients } from './database/redis';
import httpServer from './http/httpServer';
import expiredManager from './manager/expiredManager';
import connectorManager from './manager/connectorManager';
import retentionManager from './manager/retentionManager';
import ingestionManager from './manager/ingestionManager';
import taskManager from './manager/taskManager';
import ruleEngine from './manager/ruleManager';
import syncManager from './manager/syncManager';
import historyManager from './manager/historyManager';
import clusterManager from './manager/clusterManager';
import notificationManager from './manager/notificationManager';
import publisherManager from './manager/publisherManager';
import activityListener from './manager/activityListener';
import activityManager from './manager/activityManager';
import importCsvConnector from './connector/importCsv/importCsv-connector';
import { ENABLED_IMPORT_CSV_BUILT_IN_CONNECTOR } from './connector/importCsv/importCsv-configuration';
import playbookManager from './manager/playbookManager';
import fileIndexManager from './manager/fileIndexManager';
import { isAttachmentProcessorEnabled } from './database/engine';
import { UnknownError } from './config/errors';
import { startAllManagers } from './manager/managerModule';

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
  // region import csv built in connector
  if (ENABLED_IMPORT_CSV_BUILT_IN_CONNECTOR) {
    await importCsvConnector.start();
  } else {
    logApp.info('[OPENCTI-MODULE] Connector built in manager not started (disabled by configuration)');
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
  if (ENABLED_INGESTION_MANAGER) {
    await ingestionManager.start();
  } else {
    logApp.info('[OPENCTI-MODULE] Ingestion manager not started (disabled by configuration)');
  }
  // endregion
  // region History manager
  if (ENABLED_HISTORY_MANAGER) {
    await historyManager.start();
  } else {
    logApp.info('[OPENCTI-MODULE] History manager not started (disabled by configuration)');
  }
  // endregion
  // region notification
  if (ENABLED_NOTIFICATION_MANAGER) {
    await notificationManager.start();
  } else {
    logApp.info('[OPENCTI-MODULE] Notification manager not started (disabled by configuration)');
  }
  if (ENABLED_PUBLISHER_MANAGER) {
    await publisherManager.start();
  } else {
    logApp.info('[OPENCTI-MODULE] Publisher manager not started (disabled by configuration)');
  }
  // endregion
  // region playbook manager
  if (ENABLED_PLAYBOOK_MANAGER) {
    await playbookManager.start();
  } else {
    logApp.info('[OPENCTI-MODULE] Playbook manager not started (disabled by configuration)');
  }
  if (ENABLED_FILE_INDEX_MANAGER && isAttachmentProcessorEnabled()) {
    await fileIndexManager.start();
  } else if (ENABLED_FILE_INDEX_MANAGER && !isAttachmentProcessorEnabled()) {
    logApp.info('[OPENCTI-MODULE] File index manager not started : attachment processor is not configured.');
  } else {
    logApp.info('[OPENCTI-MODULE] File index manager not started (disabled by configuration)');
  }

  // refactoring in module in progress
  // all managers will be started only in this method
  await startAllManagers();

  // endregion
  // region Cluster manager
  await clusterManager.start();
  // endregion
  // region Audit
  await activityListener.start();
  await activityManager.start();
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
  // region Connector manager
  if (ENABLED_CONNECTOR_MANAGER) {
    stoppingPromises.push(connectorManager.shutdown());
  }
  // endregion
  // region import csv built in connector
  if (ENABLED_IMPORT_CSV_BUILT_IN_CONNECTOR) {
    stoppingPromises.push(importCsvConnector.shutdown());
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
  // region Ingestion managers
  if (ENABLED_SYNC_MANAGER) {
    stoppingPromises.push(syncManager.shutdown());
  }
  if (ENABLED_INGESTION_MANAGER) {
    stoppingPromises.push(ingestionManager.shutdown());
  }
  // endregion
  // region History manager
  if (ENABLED_HISTORY_MANAGER) {
    stoppingPromises.push(historyManager.shutdown());
  }
  // endregion
  // region notification
  if (ENABLED_NOTIFICATION_MANAGER) {
    stoppingPromises.push(notificationManager.shutdown());
  }
  if (ENABLED_PUBLISHER_MANAGER) {
    stoppingPromises.push(publisherManager.shutdown());
  }
  // endregion
  // region playbook manager
  if (ENABLED_PLAYBOOK_MANAGER) {
    stoppingPromises.push(playbookManager.shutdown());
  }
  // endregion
  // region Cluster manager
  stoppingPromises.push(clusterManager.shutdown());
  // endregion
  // region Audit listener
  stoppingPromises.push(activityListener.shutdown());
  stoppingPromises.push(activityManager.shutdown());
  // endregion
  await Promise.all(stoppingPromises);
};
// endregion

// region platform start and stop
export const platformStart = async () => {
  logApp.info('[OPENCTI] Starting platform');
  try {
    // Check all dependencies access
    await checkSystemDependencies();
    // Init the cache manager
    await cacheManager.start();
    // Init the platform default
    await platformInit();
    // Init the modules
    await startModules();
  } catch (e) {
    logApp.error(e);
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
};
// endregion

// region signals management
process.on('unhandledRejection', (reason, p) => {
  logApp.error(UnknownError('Engine unhandled rejection', { reason, promise: p }));
});

['SIGTERM', 'SIGINT', 'message'].forEach((signal) => {
  process.on(signal, async (message) => {
    if (signal !== 'message' || message === 'shutdown') {
      if (getStoppingState() === false) {
        setStoppingState(true);
        logApp.info(`[OPENCTI] ${signal} signal received, stopping OpenCTI`);
        try {
          await platformStop();
          process.exit(0);
        } catch (e) {
          logApp.error(e);
          process.exit(1);
        }
      }
    }
  });
});
// endregion
