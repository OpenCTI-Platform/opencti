import { logApp } from './config/conf';
import platformInit from './initialization';
import { startModules, shutdownModules } from './modules';

// eslint-disable-next-line import/prefer-default-export
export const boot = async () => {
  logApp.info(`[CYIO] Starting platform`);
  // Init the platform default
  await platformInit();
  // Init the modules
  await startModules();
};

process.on('SIGTERM', async () => {
  logApp.info('[CYIO] SIGTERM signal received, stopping OpenCTI');
  await shutdownModules();
});
