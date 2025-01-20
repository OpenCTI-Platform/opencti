import { fork } from 'child_process';
import { environment, getStoppingState, logApp, setStoppingState } from './config/conf';
import platformInit, { checkFeatureFlags, checkSystemDependencies } from './initialization';
import cacheManager from './manager/cacheManager';
import { shutdownRedisClients } from './database/redis';
import { shutdownModules, startModules } from './managers';

// region platform start and stop
export const platformStart = async () => {
  logApp.info('[OPENCTI] Starting platform', { environment });
  try {
    checkFeatureFlags();
    // Check all dependencies access
    try {
      await checkSystemDependencies();
    } catch (dependencyError) {
      logApp.error('[OPENCTI] System dependencies check failed', { cause: dependencyError });
      throw dependencyError; //  Re-throw the error to exit the main try block
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
    // -- Start the control lock manager
    const forked = fork('./build/child-lock.manager.js', { test: 'test' }, {});
    const lockResources = async (operation, ids) => {
      return new Promise((resolve, reject) => {
        forked.send({ type: 'lock', operation, ids },);
        forked.on('message', (msg) => {
          if (msg.operation === operation && msg.type === 'lock') {
            if (msg.success) {
              resolve(msg);
            } else {
              reject(msg.error);
            }
          }
        });
      });
    };
    const unlockResources = async (operation) => {
      return new Promise((resolve, reject) => {
        forked.send({ type: 'unlock', operation },);
        forked.on('message', (msg) => {
          if (msg.operation === operation && msg.type === 'unlock') {
            if (msg.success) {
              resolve(msg);
            } else {
              reject(msg.error);
            }
          }
        });
      });
    };
    try {
      const d = await lockResources('operation_id', ['id1', 'id2']);
      console.log('success locking ???? ', d);
    } catch (err) {
      console.log('err locking ???? ', err);
    }

    setTimeout(async () => {
      try {
        const d = await lockResources('operation_id', ['id1']);
        console.log('success unlocking ???? ', d);
      } catch (err) {
        console.log('err unlocking ???? ', err);
      }
    }, 15000);

    setTimeout(async () => {
      try {
        const d = await unlockResources('operation_id');
        console.log('success unlocking ???? ', d);
      } catch (err) {
        console.log('err unlocking ???? ', err);
      }
    }, 75000);
  } catch (mainError) {
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
  logApp.error('[OPENCTI] Engine unhandled rejection', { reason: reason?.stack, promise: p?.stack });
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
          logApp.error('[OPENCTI] Error stopping the platform', { cause: e });
          process.exit(1);
        }
      }
    }
  });
});
// endregion
