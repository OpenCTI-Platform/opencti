import { DEV_MODE, logger } from './config/conf';
import platformInit from './initialization';
import { listenServer, restartServer } from './httpServer';
import { redisInitializeClients } from './database/redis';

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
        logger.info('[DEV] Application has been successfully hot swapped');
      } catch (e) {
        logger.info('[DEV] Error occurred during hot swap. Node is still serving the last valid application!', {
          error: e,
        });
      }
    }
  });
  /* eslint-enable */
}

(async () => {
  try {
    logger.info(`[OPENCTI] Starting platform`);
    await platformInit();
    server = await listenServer();
  } catch (e) {
    process.exit(1);
  }
})();
