import { logApp } from './config/conf';
import platformInit, { checkSystemDependencies } from './initialization';
import { startModules, shutdownModules } from './modules';
import cacheManager from './manager/cacheManager';

// eslint-disable-next-line import/prefer-default-export
export const boot = async () => {
  logApp.info('[OPENCTI] Starting platform');
  await checkSystemDependencies();
  // Init the cache manager
  await cacheManager.start();
  // Init the platform default
  await platformInit();
  // Init the modules
  await startModules();
};

process.on('SIGTERM', async () => {
  logApp.info('[OPENCTI] SIGTERM signal received, stopping OpenCTI');
  // Shutdown the cache manager
  await cacheManager.shutdown();
  // Destroy the modules
  await shutdownModules();
  logApp.info('[OPENCTI] All modules have been stopped, exiting process');
  process.exit(0);
});

const stopProcess = async () => {
  let exitCode = 1;
  try {
    await shutdownModules();
    exitCode = 0;
  } catch (e) {
    logApp.error('[OPENCTI] OpenCTI stop error', { error: e });
  } finally {
    logApp.info('[OPENCTI] OpenCTI stopped');
    process.exit(exitCode);
  }
};

let stopping = false;
['SIGTERM', 'SIGINT', 'message'].forEach((signal) => {
  process.on(signal, (message) => {
    if (signal !== 'message' || message === 'shutdown') {
      if (!stopping) {
        stopping = true;
        logApp.info(`[OPENCTI] Shutdown ${signal} signal received, stopping OpenCTI`);
        // noinspection JSIgnoredPromiseFromCall
        stopProcess();
      }
    }
  });
});
