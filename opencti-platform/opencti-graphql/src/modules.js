import conf, {
  ENABLED_API,
  ENABLED_EXPIRED_MANAGER,
  ENABLED_SUBSCRIPTION_MANAGER,
  ENABLED_RULE_ENGINE,
  ENABLED_TASK_SCHEDULER,
  logApp,
} from './config/conf';
import expiredManager from './manager/expiredManager';
import subscriptionManager from './manager/subscriptionManager';
import taskManager from './manager/taskManager';
import ruleEngine from './manager/ruleManager';
import httpServer from './http/httpServer';

// Http server
export const startModules = async () => {
  // region API initialization
  if (ENABLED_API) {
    await httpServer.start();
    logApp.info(`[OPENCTI] API ready on port ${conf.get('app:port')}`);
  } else {
    logApp.info(`[OPENCTI] API not started (disabled by configuration)`);
  }
  // endregion
  // region Expiration manager
  if (ENABLED_EXPIRED_MANAGER) {
    await expiredManager.start();
    logApp.info(`[OPENCTI] Expiration manager started`);
  } else {
    logApp.info(`[OPENCTI] Expiration manager not started (disabled by configuration)`);
  }
  // endregion
  // region Task manager
  if (ENABLED_TASK_SCHEDULER) {
    await taskManager.start();
    logApp.info(`[OPENCTI] Task manager started`);
  } else {
    logApp.info(`[OPENCTI] Task manager not started (disabled by configuration)`);
  }
  // endregion
  // region Inference engine
  if (ENABLED_RULE_ENGINE) {
    const engineStarted = await ruleEngine.start();
    if (engineStarted) {
      logApp.info(`[OPENCTI] Rule engine started`);
    } else {
      logApp.info('[OPENCTI] Rule engine not started (already started by another instance)');
    }
  } else {
    logApp.info(`[OPENCTI] Rule engine not started (disabled by configuration)`);
  }
  // endregion
  // region Subscription manager
  if (ENABLED_SUBSCRIPTION_MANAGER) {
    await subscriptionManager.start();
    logApp.info(`[OPENCTI] Subscription manager started`);
  } else {
    logApp.info(`[OPENCTI] Subscription manager not started (disabled by configuration)`);
  }
  // endregion
};

export const shutdownModules = async () => {
  // region API initialization
  await httpServer.shutdown();
  logApp.info(`[OPENCTI] API stopped`);
  // endregion
  // region Expiration manager
  await expiredManager.shutdown();
  logApp.info(`[OPENCTI] Expiration manager stopped`);
  // endregion
  // region Task manager
  await taskManager.shutdown();
  logApp.info(`[OPENCTI] Task manager stopped`);
  // endregion
  // region Inference engine
  await ruleEngine.shutdown();
  logApp.info(`[OPENCTI] Rule engine stopped`);
  // endregion
  // region Subscription manager
  await subscriptionManager.shutdown();
  logApp.info(`[OPENCTI] Subscription manager stopped`);
  // endregion
};
