import { getStoppingState, logApp, setStoppingState } from './config/conf';
import platformInit, { checkSystemDependencies } from './initialization';
import { startModules, shutdownModules } from './modules';
import cacheManager from './manager/cacheManager';

// eslint-disable-next-line import/prefer-default-export
export const boot = async () => {
  logApp.info('[OPENCTI] Starting platform');
  try {
    await checkSystemDependencies();
    // Init the cache manager
    await cacheManager.start();
    // Init the platform default
    await platformInit();
    // Init the modules
    await startModules();
  } catch (e) {
    logApp.error('[OPENCTI] Platform start fail', { error: e });
    process.exit(1);
  }
};

const stopProcess = async () => {
  let exitCode = 1;
  try {
    // Shutdown the cache manager
    await cacheManager.shutdown();
    // Destroy the modules
    await shutdownModules();
    exitCode = 0;
  } catch (e) {
    logApp.error('[OPENCTI] OpenCTI stop error', { error: e });
  } finally {
    logApp.info('[OPENCTI] All modules have been stopped, exiting process');
    process.exit(exitCode);
  }
};

['SIGTERM', 'SIGINT', 'message'].forEach((signal) => {
  process.on(signal, (message) => {
    if (signal !== 'message' || message === 'shutdown') {
      if (getStoppingState() === false) {
        setStoppingState(true);
        logApp.info(`[OPENCTI] ${signal} signal received, stopping OpenCTI`);
        // noinspection JSIgnoredPromiseFromCall
        stopProcess();
        logApp.info(`[OPENCTI] Shutdown ${signal} signal received, stopping OpenCTI`);
      }
    }
  });
});
