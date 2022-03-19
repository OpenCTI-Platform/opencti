import { logApp } from './config/conf';
import platformInit from './initialization';
import { startModules, shutdownModules } from './modules';

// eslint-disable-next-line import/prefer-default-export
export const boot = async () => {
  logApp.info('[OPENCTI] Starting platform');
  // Init the platform default
  await platformInit();
  // Init the modules
  await startModules();
};

process.on('SIGTERM', async () => {
  logApp.info('[OPENCTI] SIGTERM signal received, stopping OpenCTI');
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
