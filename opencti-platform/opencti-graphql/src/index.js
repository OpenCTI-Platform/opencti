import conf, { DEV_MODE, logger } from './config/conf';
import init from './initialization';
import createHttpServer from './httpServer';

// Server creation
const PORT = conf.get('app:port');

let httpServer;
const listenServer = () => {
  return new Promise((resolve, reject) => {
    try {
      httpServer = createHttpServer();
      httpServer.listen(PORT, () => {
        logger.info(`OPENCTI Ready on port ${PORT}`);
        resolve();
      });
    } catch (e) {
      reject(e);
    }
  });
};
const restartServer = () => {
  return new Promise((resolve, reject) => {
    httpServer.close(() => {
      logger.info('OPENCTI server stopped');
      listenServer()
        .then(() => resolve())
        .catch(e => reject(e));
    });
    httpServer.emit('close'); // force server close
  });
};

// Hot reload
if (DEV_MODE && module.hot) {
  /* eslint-disable no-console, global-require, import/no-extraneous-dependencies */
  require('webpack/hot/log').setLogLevel('warning');
  module.hot.accept(['./httpServer', './initialization'], async updated => {
    const httpUpdated = updated.includes('./src/httpServer.js');
    const appUpdated = updated.includes('./src/initialization.js');
    if (httpUpdated || appUpdated) {
      try {
        await restartServer();
        logger.info('Application has been successfully hot swapped');
      } catch (e) {
        logger.info('Error occurred during hot swap. Node is still serving the last valid application!');
        logger.error(`${e.stack ? e.stack : e}`);
      }
    }
  });
  /* eslint-enable */
}

(async () => {
  try {
    await init();
    await listenServer();
  } catch (e) {
    logger.error(`[OPENCTI] GraphQL initialization fail > ${e.stack ? e.stack : e}`);
    process.exit(1);
  }
})();
