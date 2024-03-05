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
    try {
      await checkSystemDependencies();
    } catch (dependencyError) {
      logApp.error('[OPENCTI] System dependencies check failed', {
        dependencyError,
      });
      throw dependencyError; // Re-throw the error to exit the main try block
    }

    // Init the cache manager
    try {
      await cacheManager.start();
    } catch (cacheError) {
      logApp.error('[OPENCTI] Cache manager initialization failed', {
        cacheError,
      });
      throw cacheError;
    }
    // Init the platform default
    try {
      await platformInit();
    } catch (platformError) {
      logApp.error('[OPENCTI] Platform default initialization failed', {
        platformError,
      });
      throw platformError;
    }
    // Init the modules
    try {
      await startModules();
    } catch (modulesError) {
      logApp.error('[OPENCTI] Modules startup failed', { modulesError });
      throw modulesError;
    }
  } catch (mainError) {
    logApp.error(mainError);
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
