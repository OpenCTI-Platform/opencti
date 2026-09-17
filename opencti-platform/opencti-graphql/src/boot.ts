import { environment, getStoppingState, logApp, setStoppingState } from './config/conf';
import platformInit, { checkFeatureFlags } from './initialization';
import cacheManager from './manager/cacheManager';
import { shutdownRedisClients } from './database/redis';
import { shutdownModules, startModules } from './managers';
import { initLockFork } from './lock/master-lock';
import { checkSystemDependencies } from './boot-utils';
import { startLivenessServer, stopLivenessServer } from './http/httpLiveness';
import { startEngineHealthMonitor, stopEngineHealthMonitor } from './database/engine-monitoring';
import { startPlatformHealthMonitor, stopPlatformHealthMonitor } from './telemetry/platformHealthMetrics';

// region platform start and stop
// Track the in-flight startup so a shutdown signal received while the platform is still
// starting (e.g. during a hot-reload restart) can wait for it to settle instead of killing
// the process mid-initialization. Doing so guarantees resources such as the platform init
// lock are always released through their normal try/finally instead of being left stale
// in Redis until their TTL expires.
let platformStartPromise: Promise<void> | undefined;

export const platformStart = async () => {
  platformStartPromise = doPlatformStart();
  await platformStartPromise;
};

const doPlatformStart = async () => {
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
    // Start the platform health monitoring before the API so /health can answer from collected state
    try {
      await startPlatformHealthMonitor();
    } catch (healthMonitorError) {
      logApp.error('[OPENCTI] Platform health monitoring startup failed', { cause: healthMonitorError });
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
  // Stop the platform health monitoring
  stopPlatformHealthMonitor();
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
          // If the platform is still starting (e.g. a hot-reload restart raced with the
          // previous instance's initialization), wait for it to settle first so resources
          // such as the platform init lock are released through their normal try/finally
          // instead of being abandoned mid-acquisition until their TTL expires.
          if (platformStartPromise) {
            await platformStartPromise.catch(() => {
              // Startup already logs and handles its own failures; nothing more to do here.
            });
          }
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
