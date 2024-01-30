import { getStoppingState, logApp, setStoppingState } from './config/conf';
import platformInit, { checkSystemDependencies } from './initialization';
import cacheManager from './manager/cacheManager';
import { shutdownRedisClients } from './database/redis';
import { UnknownError } from './config/errors';
import { shutdownModules, startModules } from './managers';

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
