import { logApp } from './config/conf';
import platformInit from './initialization';
import { startModules, shutdownModules } from './modules';

// eslint-disable-next-line import/prefer-default-export
export const boot = async () => {
  logApp.info(`[OPENCTI] Starting platform`);
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
