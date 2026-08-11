import { environment, getStoppingState, logApp, setStoppingState } from './config/conf';
import platformInit, { checkFeatureFlags } from './initialization';
import cacheManager from './manager/cacheManager';
import { shutdownRedisClients } from './database/redis';
import { shutdownModules, startModules } from './managers';
import { initLockFork } from './lock/master-lock';
import { checkSystemDependencies } from './boot-utils';
import { startLivenessServer, stopLivenessServer } from './http/httpLiveness';
import { startEngineHealthMonitor, stopEngineHealthMonitor } from './database/engine-monitoring';

// region platform start and stop
export const platformStart = async () => {
  const startTime = Date.now();
  logApp.info('[OPENCTI] Starting platform', { environment });
  try {
    // Start the liveness probe first so orchestrators can detect the process is alive
    try {
      startLivenessServer();
    } catch (livenessError) {
      logApp.error('[OPENCTI] Liveness server startup failed', { cause: livenessError });
      throw livenessError;
    }
    checkFeatureFlags();
    // Check all dependencies access
    try {
      await checkSystemDependencies();
    } catch (dependencyError) {
      logApp.error('[OPENCTI] System dependencies check failed', { cause: dependencyError });
      throw dependencyError; //  Re-throw the error to exit the main try block
    }
    // Init the lock manager
    try {
      initLockFork();
    } catch (lockManagerError) {
      logApp.error('[OPENCTI] Lock process startup failed', { cause: lockManagerError });
      throw lockManagerError;
    }
    // Init the cache manager
    try {
      await cacheManager.start();
    } catch (cacheError) {
      logApp.error('[OPENCTI] Cache manager initialization failed', { cause: cacheError });
      throw cacheError;
    }
    // Init the platform default
    try {
      await platformInit();
    } catch (platformError) {
      logApp.error('[OPENCTI] Platform default initialization failed', { cause: platformError });
      throw platformError;
    }
    // Init the modules
    try {
      await startModules();
    } catch (modulesError) {
      logApp.error('[OPENCTI] Modules startup failed', { cause: modulesError });
      throw modulesError;
    }
    // Start the engine health monitoring CRON
    startEngineHealthMonitor();
    logApp.info(`[OPENCTI] Platform started ${Date.now() - startTime} ms`);
  } catch (_mainError) {
    process.exit(1);
  }
};

export const platformStop = async () => {
  const stopTime = new Date().getTime();
  // Shutdown the liveness probe
  await stopLivenessServer();
  // Stop the engine health monitoring CRON
  stopEngineHealthMonitor();
  // Shutdown the cache manager
  await cacheManager.shutdown();
  // Destroy the modules
  await shutdownModules();
  // Shutdown the redis clients
  shutdownRedisClients();
  logApp.info(`[OPENCTI] Platform stopped ${new Date().getTime() - stopTime} ms`);
};
// endregion

// region signals management
process.on('unhandledRejection', (reason: Error) => {
  logApp.error('[OPENCTI] Engine unhandled rejection', { reason: reason?.stack });
});

['SIGTERM', 'SIGINT', 'message'].forEach((signal) => {
  process.on(signal, async (message) => {
    if (signal !== 'message' || message === 'shutdown') {
      if (!getStoppingState()) {
        setStoppingState(true);
        logApp.info(`[OPENCTI] ${signal} signal received, stopping OpenCTI`);
        try {
          await platformStop();
          process.exit(0);
        } catch (e) {
          logApp.error('[OPENCTI] Error stopping the platform', { cause: e });
          process.exit(1);
        }
      }
    }
  });
});
// endregion
