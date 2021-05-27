import conf, { DEV_MODE, logApp } from './config/conf';
import platformInit from './initialization';
import { listenServer, restartServer, stopServer } from './httpServer';
import { redisInitializeClients } from './database/redis';
import initExpiredManager from './manager/expiredManager';
import initTaskManager from './manager/taskManager';
import initRuleManager from './manager/ruleManager';
import 'source-map-support/register';

let server;
if (DEV_MODE && module.hot) {
  /* eslint-disable no-console, global-require, import/no-extraneous-dependencies */
  require('webpack/hot/log').setLogLevel('warning');
  module.hot.accept(['./httpServer', './initialization'], async (updated) => {
    const httpUpdated = updated.includes('./src/httpServer.js');
    const appUpdated = updated.includes('./src/initialization.js');
    if (httpUpdated || appUpdated) {
      try {
        await redisInitializeClients();
        server = await restartServer(server);
        logApp.info('[DEV] Application has been successfully hot swapped');
      } catch (e) {
        logApp.info('[DEV] Error occurred during hot swap. Node is still serving the last valid application!', {
          error: e,
        });
      }
    }
  });
  /* eslint-enable */
}

const API_PORT = conf.get('app:port');
const ENABLED_API = conf.get('app:enabled');
const ENABLED_EXPIRED_MANAGER = conf.get('expiration_scheduler:enabled');
const expiredManager = initExpiredManager();
const ENABLED_TASK_SCHEDULER = conf.get('task_scheduler:enabled');
const taskManager = initTaskManager();
const ENABLED_RULE_ENGINE = conf.get('rule_engine:enabled');
const ruleEngine = initRuleManager();
(async () => {
  try {
    logApp.info(`[OPENCTI] Starting platform`);
    // Init the platform default
    await platformInit();
    // region API initialization
    if (ENABLED_API) {
      server = await listenServer();
      logApp.info(`[OPENCTI] API ready on port ${API_PORT}`);
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
  } catch (e) {
    process.exit(1);
  }
})();

process.on('SIGTERM', async () => {
  logApp.info('[OPENCTI] SIGTERM signal received, stopping OpenCTI');
  if (server) {
    await stopServer(server);
  }
  await expiredManager.shutdown();
  await taskManager.shutdown();
  await ruleEngine.shutdown();
});
