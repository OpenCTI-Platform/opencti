import conf, {
  ENABLED_API,
  ENABLED_EXPIRED_MANAGER,
  ENABLED_SUBSCRIPTION_MANAGER,
  ENABLED_RULE_ENGINE,
  ENABLED_TASK_SCHEDULER,
  logApp,
  ENABLED_SYNC_MANAGER,
} from './config/conf';
import expiredManager from './manager/expiredManager';
import subscriptionManager from './manager/subscriptionManager';
import taskManager from './manager/taskManager';
import ruleEngine from './manager/ruleManager';
import syncManager from './manager/syncManager';
import httpServer from './http/httpServer';

// Http server
export const startModules = async () => {
  // region API initialization
  if (ENABLED_API) {
    await httpServer.start();
    logApp.info(`[CYIO] API ready on port ${conf.get('app:port')}`);
  } else {
    logApp.info(`[CYIO] API not started (disabled by configuration)`);
  }
  // endregion
  // region Expiration manager
  if (ENABLED_EXPIRED_MANAGER) {
    await expiredManager.start();
    logApp.info(`[CYIO] Expiration manager started`);
  } else {
    logApp.info(`[CYIO] Expiration manager not started (disabled by configuration)`);
  }
  // endregion
  // region Task manager
  if (ENABLED_TASK_SCHEDULER) {
    await taskManager.start();
    logApp.info(`[CYIO] Task manager started`);
  } else {
    logApp.info(`[CYIO] Task manager not started (disabled by configuration)`);
  }
  // endregion
  // region Inference engine
  if (ENABLED_RULE_ENGINE) {
    const engineStarted = await ruleEngine.start();
    if (engineStarted) {
      logApp.info(`[CYIO] Rule engine started`);
    } else {
      logApp.info('[CYIO] Rule engine not started (already started by another instance)');
    }
  } else {
    logApp.info(`[CYIO] Rule engine not started (disabled by configuration)`);
  }
  // endregion
  // region Subscription manager
  if (ENABLED_SUBSCRIPTION_MANAGER) {
    await subscriptionManager.start();
    logApp.info(`[CYIO] Subscription manager started`);
  } else {
    logApp.info(`[CYIO] Subscription manager not started (disabled by configuration)`);
  }
  // endregion
  // region Sync manager
  if (ENABLED_SYNC_MANAGER) {
    await syncManager.start();
    logApp.info(`[CYIO] Sync manager started`);
  } else {
    logApp.info(`[CYIO] Sync manager not started (disabled by configuration)`);
  }
  // endregion
};

export const shutdownModules = async () => {
  // region API initialization
  await httpServer.shutdown();
  logApp.info(`[CYIO] API stopped`);
  // endregion
  // region Expiration manager
  await expiredManager.shutdown();
  logApp.info(`[CYIO] Expiration manager stopped`);
  // endregion
  // region Task manager
  await taskManager.shutdown();
  logApp.info(`[CYIO] Task manager stopped`);
  // endregion
  // region Inference engine
  await ruleEngine.shutdown();
  logApp.info(`[CYIO] Rule engine stopped`);
  // endregion
  // region Subscription manager
  await subscriptionManager.shutdown();
  logApp.info(`[CYIO] Subscription manager stopped`);
  // endregion
  // region Sync manager
  await syncManager.shutdown();
  logApp.info(`[CYIO] Sync manager stopped`);
  // endregion
};
