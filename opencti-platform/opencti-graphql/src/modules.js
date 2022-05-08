import conf, {
  ENABLED_API,
  ENABLED_EXPIRED_MANAGER,
  ENABLED_SUBSCRIPTION_MANAGER,
  ENABLED_RULE_ENGINE,
  ENABLED_TASK_SCHEDULER,
  logApp,
  ENABLED_SYNC_MANAGER,
  ENABLED_RETENTION_MANAGER,
  ENABLED_HISTORY_MANAGER,
} from './config/conf';
import expiredManager from './manager/expiredManager';
import subscriptionManager from './manager/subscriptionManager';
import taskManager from './manager/taskManager';
import ruleEngine from './manager/ruleManager';
import historyManager from './manager/historyManager';
import syncManager from './manager/syncManager';
import retentionManager from './manager/retentionManager';
import httpServer from './http/httpServer';

// Http server
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
  // region Subscription manager
  if (ENABLED_SUBSCRIPTION_MANAGER) {
    await subscriptionManager.start();
  } else {
    logApp.info('[OPENCTI-MODULE] Subscription manager not started (disabled by configuration)');
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
};

export const shutdownModules = async () => {
  // region API initialization
  await httpServer.shutdown();
  logApp.info('[OPENCTI] API stopped');
  // endregion
  // region Expiration manager
  await expiredManager.shutdown();
  logApp.info('[OPENCTI-MODULE] Expiration manager stopped');
  // endregion
  // region Retention manager
  await retentionManager.shutdown();
  logApp.info('[OPENCTI-MODULE] Retention manager stopped');
  // endregion
  // region Task manager
  await taskManager.shutdown();
  logApp.info('[OPENCTI-MODULE] Task manager stopped');
  // endregion
  // region Inference engine
  await ruleEngine.shutdown();
  logApp.info('[OPENCTI-MODULE] Rule engine stopped');
  // endregion
  // region Subscription manager
  await subscriptionManager.shutdown();
  logApp.info('[OPENCTI-MODULE] Subscription manager stopped');
  // endregion
  // region Sync manager
  await syncManager.shutdown();
  logApp.info('[OPENCTI-MODULE] Sync manager stopped');
  // endregion
  // region History manager
  await historyManager.shutdown();
  logApp.info('[OPENCTI-MODULE] History manager stopped');
  // endregion
};
