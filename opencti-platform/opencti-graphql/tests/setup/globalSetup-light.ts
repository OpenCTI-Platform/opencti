// region static graphql modules, need to be imported before everything
import '../../src/modules/index';
// import managers
import '../../src/manager/index';
// endregion
import { initializeBucket } from '../../src/database/raw-file-storage';
import { initializeSchema } from '../../src/database/engine';
import { logApp } from '../../src/config/conf';
import cacheManager from '../../src/manager/cacheManager';
import { initDefaultNotifiers } from '../../src/modules/notifier/notifier-domain';
import { initializeInternalQueues } from '../../src/database/rabbitmq';
import { executionContext } from '../../src/utils/access';
import { initializeData } from '../../src/database/data-initialization';
import { initExclusionListCache } from '../../src/database/exclusionListCache';
import { initLockFork } from '../../src/lock/master-lock';
import { createTestUsers, isPlatformAlive } from '../utils/testQuery';
import { initializeStreamStack } from '../../src/database/stream/stream-handler';
import { initializeAuthenticationProviders } from '../../src/modules/authenticationProvider/providers';
import { initializeAdminUser } from '../../src/domain/user';
import { checkSystemDependencies } from '../../src/boot-utils';
import { wait } from '../../src/database/utils';

/**
 * Light global setup for the integration-light test suite.
 *
 * Differences from the full globalSetup.ts:
 * - NO destructive cleanup (no index/queue/bucket deletion)
 * - NO startModules() (no heavy managers)
 * - Initializes platform data (Settings, markings, admin user, test users)
 * - Starts the cache manager so tests can access Settings from cache
 */

const initializePlatform = async () => {
  const context = executionContext('platform_test_initialization_light');
  logApp.info('[vitest-global-setup-light] Initializing platform data...');
  const stopTime = new Date().getTime();

  await initializeInternalQueues();
  await initializeStreamStack();
  await initializeBucket();
  await initializeSchema();
  await initializeData(context, true);
  await initializeAdminUser(context);
  await initDefaultNotifiers(context);
  await initializeAuthenticationProviders(context);
  logApp.info(`[vitest-global-setup-light] Platform initialized in ${new Date().getTime() - stopTime} ms`);
};

const waitPlatformIsAlive = async (): Promise<true> => {
  const startTime = new Date().getTime();
  const isAlive = await isPlatformAlive();
  if (!isAlive) {
    logApp.info('[vitest-global-setup-light] ping platform ...');
    await wait(1000);
    return waitPlatformIsAlive();
  }
  logApp.info(`[vitest-global-setup-light] platform is alive in ${new Date().getTime() - startTime} ms`);
  return true;
};

export async function setup() {
  const stopTime = new Date().getTime();
  await checkSystemDependencies();
  initLockFork();

  // Start cache manager (needed for getEntityFromCache to work in tests)
  await cacheManager.start();
  await initExclusionListCache();

  // Initialize platform data (Settings, markings, admin user) — no cleanup
  await initializePlatform();

  // Wait for platform to be alive and create test users
  await waitPlatformIsAlive();
  logApp.info('[vitest-global-setup-light] Creating test users...');
  await createTestUsers();

  logApp.info(`[vitest-global-setup-light] Setup done in ${new Date().getTime() - stopTime} ms`);
}

export async function teardown() {
  // Let vite kill the process — no cleanup needed for light suite
}
