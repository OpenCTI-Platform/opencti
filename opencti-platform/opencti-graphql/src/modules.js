import conf, {
  ENABLED_API,
  ENABLED_CONNECTOR_MANAGER,
  ENABLED_EXPIRED_MANAGER,
  ENABLED_HISTORY_MANAGER,
  ENABLED_NOTIFICATION_MANAGER, ENABLED_PUBLISHER_MANAGER,
  ENABLED_RETENTION_MANAGER,
  ENABLED_RULE_ENGINE,
  ENABLED_SYNC_MANAGER,
  ENABLED_TASK_SCHEDULER,
  logApp,
} from './config/conf';
import expiredManager from './manager/expiredManager';
import taskManager from './manager/taskManager';
import ruleEngine from './manager/ruleManager';
import historyManager from './manager/historyManager';
import syncManager from './manager/syncManager';
import retentionManager from './manager/retentionManager';
import httpServer from './http/httpServer';
import connectorManager from './manager/connectorManager';
import clusterManager from './manager/clusterManager';
import notificationManager from './manager/notificationManager';
import publisherManager from './manager/publisherManager';

// region static graphql modules
import './modules/index';
// endregion

// region dynamic modules
export const startModules = async () => {
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
  // region Notification manager
  if (ENABLED_NOTIFICATION_MANAGER) {
    await notificationManager.start();
  } else {
    logApp.info('[OPENCTI-MODULE] Notification manager not started (disabled by configuration)');
  }
  // endregion
  // region Notification manager
  if (ENABLED_PUBLISHER_MANAGER) {
    await publisherManager.start();
  } else {
    logApp.info('[OPENCTI-MODULE] Publisher manager not started (disabled by configuration)');
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

export const shutdownModules = async () => {
  // region API shutdown
  let stopTime;
  if (ENABLED_API) {
    stopTime = new Date().getTime();
    await httpServer.shutdown();
    logApp.info(`[OPENCTI] API stopped in ${new Date().getTime() - stopTime} ms`);
  }
  // endregion
  // region Expiration manager
  if (ENABLED_EXPIRED_MANAGER) {
    stopTime = new Date().getTime();
    await expiredManager.shutdown();
    logApp.info(`[OPENCTI-MODULE] Expiration manager stopped in ${new Date().getTime() - stopTime} ms`);
  }
  // endregion
  // region Retention manager
  if (ENABLED_RETENTION_MANAGER) {
    stopTime = new Date().getTime();
    await retentionManager.shutdown();
    logApp.info(`[OPENCTI-MODULE] Retention manager stopped in ${new Date().getTime() - stopTime} ms`);
  }
  // endregion
  // region Notification manager
  if (ENABLED_NOTIFICATION_MANAGER) {
    stopTime = new Date().getTime();
    await notificationManager.shutdown();
    logApp.info(`[OPENCTI-MODULE] Notification manager stopped in ${new Date().getTime() - stopTime} ms`);
  }
  // endregion
  // region Publisher manager
  if (ENABLED_PUBLISHER_MANAGER) {
    stopTime = new Date().getTime();
    await publisherManager.shutdown();
    logApp.info(`[OPENCTI-MODULE] Publisher manager stopped in ${new Date().getTime() - stopTime} ms`);
  }
  // endregion
  // region Task manager
  if (ENABLED_TASK_SCHEDULER) {
    stopTime = new Date().getTime();
    await taskManager.shutdown();
    logApp.info(`[OPENCTI-MODULE] Task manager stopped in ${new Date().getTime() - stopTime} ms`);
  }
  // endregion
  // region Inference engine
  if (ENABLED_RULE_ENGINE) {
    stopTime = new Date().getTime();
    await ruleEngine.shutdown();
    logApp.info(`[OPENCTI-MODULE] Rule engine stopped in ${new Date().getTime() - stopTime} ms`);
  }
  // endregion
  // region Sync manager
  if (ENABLED_SYNC_MANAGER) {
    stopTime = new Date().getTime();
    await syncManager.shutdown();
    logApp.info(`[OPENCTI-MODULE] Sync manager stopped in ${new Date().getTime() - stopTime} ms`);
  }
  // endregion
  // region History manager
  if (ENABLED_HISTORY_MANAGER) {
    stopTime = new Date().getTime();
    await historyManager.shutdown();
    logApp.info(`[OPENCTI-MODULE] History manager stopped in ${new Date().getTime() - stopTime} ms`);
  }
  // endregion
  // region Cluster manager
  stopTime = new Date().getTime();
  await clusterManager.shutdown();
  logApp.info(`[OPENCTI-MODULE] Cluster manager stopped in ${new Date().getTime() - stopTime} ms`);
  // endregion
};
// endregion
