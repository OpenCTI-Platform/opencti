import { DEV_MODE, logger } from './config/conf';
import platformInit from './initialization';
import { listenServer, restartServer } from './httpServer';

(async () => {
  try {
    await platformInit();
    let server = await listenServer();
    // Hot reload
    if (DEV_MODE && module.hot) {
      /* eslint-disable no-console, global-require, import/no-extraneous-dependencies */
      require('webpack/hot/log').setLogLevel('warning');
      module.hot.accept(['./httpServer', './initialization'], async (updated) => {
        const httpUpdated = updated.includes('./src/httpServer.js');
        const appUpdated = updated.includes('./src/initialization.js');
        if (httpUpdated || appUpdated) {
          try {
            server = await restartServer(server);
            logger.info('Application has been successfully hot swapped');
          } catch (e) {
            logger.info('Error occurred during hot swap. Node is still serving the last valid application!');
            logger.error(`${e.stack ? e.stack : e}`);
          }
        }
      });
      /* eslint-enable */
    }
  } catch (e) {
    logger.error(`[OPENCTI] GraphQL initialization fail > ${e.stack ? e.stack : e}`);
    process.exit(1);
  }
})();
