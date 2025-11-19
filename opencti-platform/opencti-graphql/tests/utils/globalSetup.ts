// region static graphql modules, need to be imported before everything
import '../../src/modules/index';
// import managers
import '../../src/manager/index';
// endregion
import { storageInit, initializeBucket } from '../../src/database/raw-file-storage';
import { deleteQueues } from '../../src/domain/connector';
import { ADMIN_USER, createTestUsers, isPlatformAlive, testContext } from './testQuery';
import { elDeleteIndices, elPlatformIndices, initializeSchema, searchEngineInit } from '../../src/database/engine';
import { wait } from '../../src/database/utils';
import { createRedisClient, initializeRedisClients, shutdownRedisClients } from '../../src/database/redis';
import { logApp, environment } from '../../src/config/conf';
import cacheManager from '../../src/manager/cacheManager';
import { initializeAdminUser } from '../../src/config/providers';
import { initDefaultNotifiers } from '../../src/modules/notifier/notifier-domain';
import { initializeInternalQueues } from '../../src/database/rabbitmq';
import { executionContext } from '../../src/utils/access';
import { initializeData } from '../../src/database/data-initialization';
import { shutdownModules, startModules } from '../../src/managers';
import { deleteAllBucketContent } from '../../src/database/file-storage';
import { initExclusionListCache } from '../../src/database/exclusionListCache';
import { initLockFork } from '../../src/lock/master-lock';

/**
 * This is run once before all tests (for setup) and after all (for teardown).
 *
 * Vitest setup is configurable with environment variables, as you can see in our package.json scripts
 *   INIT_TEST_PLATFORM=1 > cleanup the test platform, removing elastic indices, and setup it again
 *   SKIP_CLEANUP_PLATFORM=1 > skip cleanup, and directly start the platform
 *
 * run yarn test:dev:init to cleanup and reinit a test platform (it also provision the data)
 * run yarn test:dev:resume <file-pattern> to run directly some tests without cleanup and init of the test platform
 */

const { INIT_TEST_PLATFORM, SKIP_CLEANUP_PLATFORM } = process.env;

const initializePlatform = async () => {
  const context = executionContext('platform_test_initialization');
  logApp.info(`[vitest-global-setup] initializing platform with env=${environment}`);
  const stopTime = new Date().getTime();

  await initializeInternalQueues();
  await initializeBucket();
  await initializeSchema();
  await initializeData(context, true);
  await initializeAdminUser(context);
  await initDefaultNotifiers(context);
  logApp.info(`[vitest-global-setup] Platform initialized in ${new Date().getTime() - stopTime} ms`);
};

const testPlatformStart = async () => {
  const stopTime = new Date().getTime();
  logApp.info('[vitest-global-setup] Starting platform');
  try {
    // Init the cache manager
    await cacheManager.start();
    // Init the exclusion list cache
    await initExclusionListCache();
    // Init the platform default if it was cleaned up
    if (!SKIP_CLEANUP_PLATFORM) {
      await initializePlatform();
    }
    // Init the modules
    await startModules();
    logApp.info(`[vitest-global-setup] Platform started in ${new Date().getTime() - stopTime} ms`);
  } catch (e) {
    logApp.error(e);
    process.exit(1);
  }
};

const testPlatformStop = async () => {
  logApp.info('[vitest-global-setup] stopping platform');
  const stopTime = new Date().getTime();
  // Shutdown the cache manager
  await cacheManager.shutdown();
  // Destroy the modules
  await shutdownModules();
  // Shutdown the redis clients
  shutdownRedisClients();
  logApp.info(`[vitest-global-setup] Platform stopped in ${new Date().getTime() - stopTime} ms`);
};

const platformClean = async () => {
  logApp.info('[vitest-global-setup] cleaning up platform');
  const stopTime = new Date().getTime();
  // Delete the bucket
  await deleteAllBucketContent(testContext, ADMIN_USER);
  // Delete all rabbitmq queues
  await deleteQueues(testContext, ADMIN_USER);
  // Remove all elastic indices
  const indices = await elPlatformIndices();
  await elDeleteIndices(indices.map((i: { index: number }) => i.index));
  // Delete redis streams
  const testRedisClient = await createRedisClient('reset');
  await testRedisClient.del('stream.opencti');
  testRedisClient.disconnect();
  logApp.info(`[vitest-global-setup] Platform cleaned up in ${new Date().getTime() - stopTime} ms`);
};

const waitPlatformIsAlive = async (): Promise<true> => {
  const isAlive = await isPlatformAlive();
  if (!isAlive) {
    logApp.info('[vitest-global-setup] ping platform ...');
    await wait(1000);
    return waitPlatformIsAlive();
  }
  logApp.info('[vitest-global-setup] platform is alive');
  return true;
};

export async function setup() {
  await initializeRedisClients();
  await searchEngineInit();
  await storageInit();
  initLockFork();
  // cleanup and setup a seeded platform, with all the tests users, ready to run some tests.
  if (INIT_TEST_PLATFORM) {
    logApp.info('[vitest-global-setup] only running test platform initialization');
    const stopTime = new Date().getTime();
    await platformClean();
    await testPlatformStart();
    await waitPlatformIsAlive();
    logApp.info('[vitest-global-setup] creating test users');
    await createTestUsers();
    logApp.info(`[vitest-global-setup] Test Platform initialization done in ${new Date().getTime() - stopTime} ms`);
    return;
  }

  if (!SKIP_CLEANUP_PLATFORM) {
    // Platform cleanup before executing tests
    logApp.info('[vitest-global-setup] Cleaning up test platform...');
    await platformClean();
  } else {
    logApp.info('[vitest-global-setup] !!! skipping platform cleanup and setup - database state is the same as your last run !!!');
  }
  // Start the platform
  await testPlatformStart();

  // setup tests users
  if (!SKIP_CLEANUP_PLATFORM) {
    await waitPlatformIsAlive();
    logApp.info('[vitest-global-setup] Creating test users...');
    await createTestUsers();
  }
}

export async function teardown() {
  // Stop the platform
  await testPlatformStop();
}
