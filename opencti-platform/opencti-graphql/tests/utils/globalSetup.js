// region static graphql modules, need to be imported before everything
import '../../src/modules/index';
// import managers
import '../../src/manager/index';
// endregion
import { deleteBucket, initializeBucket } from '../../src/database/file-storage';
import { deleteQueues } from '../../src/domain/connector';
import { ADMIN_USER, createTestUsers, testContext } from './testQuery';
import { elDeleteIndices, elPlatformIndices, initializeSchema, searchEngineInit } from '../../src/database/engine';
import { wait } from '../../src/database/utils';
import { createRedisClient, shutdownRedisClients } from '../../src/database/redis';
import { logApp } from '../../src/config/conf';
import cacheManager from '../../src/manager/cacheManager';
import { initializeAdminUser } from '../../src/config/providers';
import { initDefaultNotifiers } from '../../src/modules/notifier/notifier-domain';
import { initializeInternalQueues } from '../../src/database/rabbitmq';
import { executionContext } from '../../src/utils/access';
import { initializeData } from '../../src/database/data-initialization';
import { shutdownModules, startModules } from '../../src/managers';

/**
 * Vitest setup is configurable with environment variables, as you can see in our package.json scripts
 *   ONLY_PLATFORM_INIT=1 > cleanup the test platform, removing elastic indices, and setup it again
 *   SKIP_CLEANUP_PLATFORM_AT_START=1 > skip cleanup, and directly start the platform
 *
 * run yarn test:dev-init-only to cleanup and reinit a test platform (it also provision the data)
 * run yarn test:dev-no-cleanup <file-pattern> to run directly some tests without cleanup and init of the test platform
 */

const { ONLY_PLATFORM_INIT, SKIP_CLEANUP_PLATFORM_AT_START } = process.env;

const initializePlatform = async () => {
  const context = executionContext('platform_test_initialization');
  console.log('🚀 [vitest-global-setup] initializing platform');
  const stopTime = new Date().getTime();

  await initializeInternalQueues();
  await initializeBucket();
  await initializeSchema();
  await initializeData(context, true);
  await initializeAdminUser(context);
  await initDefaultNotifiers(context);
  console.log(`🚀 [vitest-global-setup] Platform initialized in ${new Date().getTime() - stopTime} ms`);
};

const testPlatformStart = async () => {
  const stopTime = new Date().getTime();
  console.log('🚀 [vitest-global-setup] Starting platform');
  try {
    // Check all dependencies access
    await searchEngineInit();
    // Init the cache manager
    await cacheManager.start();
    // Init the platform default if it was cleaned up
    if (!SKIP_CLEANUP_PLATFORM_AT_START) {
      await initializePlatform();
    }
    // Init the modules
    await startModules();
    console.log(`🚀 [vitest-global-setup] Platform started in ${new Date().getTime() - stopTime} ms`);
  } catch (e) {
    logApp.error(e);
    process.exit(1);
  }
};

const testPlatformStop = async () => {
  console.log('🚀 [vitest-global-setup] stopping platform');
  const stopTime = new Date().getTime();
  // Shutdown the cache manager
  await cacheManager.shutdown();
  // Destroy the modules
  await shutdownModules();
  // Shutdown the redis clients
  await shutdownRedisClients();
  console.log(`🚀 [vitest-global-setup] Platform stopped in ${new Date().getTime() - stopTime} ms`);
};

const platformClean = async () => {
  console.log('🚀 [vitest-global-setup] cleaning up platform');
  const stopTime = new Date().getTime();
  // Delete the bucket
  await deleteBucket();
  // Delete all rabbitmq queues
  await deleteQueues(testContext, ADMIN_USER);
  // Remove all elastic indices
  const indices = await elPlatformIndices();
  await elDeleteIndices(indices.map((i) => i.index));
  // Delete redis streams
  const testRedisClient = createRedisClient('reset');
  await testRedisClient.del('stream.opencti');
  testRedisClient.disconnect();
  console.log(`🚀 [vitest-global-setup] Platform cleaned up in ${new Date().getTime() - stopTime} ms`);
};

export async function setup() {
  if (ONLY_PLATFORM_INIT) {
    console.log('🚀 [vitest-global-setup] only running test platform initialization');
    const stopTime = new Date().getTime();
    await platformClean();
    await testPlatformStart();
    await wait(15000); // Wait 15 secs for complete platform start
    console.log('🚀 [vitest-global-setup] creating test users');
    await createTestUsers();
    console.log(`🚀 [vitest-global-setup] Test Platform initialization done in ${new Date().getTime() - stopTime} ms`);
    return;
  }

  if (!SKIP_CLEANUP_PLATFORM_AT_START) {
    // Platform cleanup before executing tests
    console.log('🚀 [vitest-global-setup] Cleaning up test platform...');
    await platformClean();
  } else {
    console.log('🚀 [vitest-global-setup] ⚠️ skipping platform cleanup and setup - database state is the same as your last run ⚠️');
  }
  // Start the platform
  await testPlatformStart();

  // setup tests users
  if (!SKIP_CLEANUP_PLATFORM_AT_START) {
    await wait(15000); // Wait 15 secs for complete platform start
    console.log('🚀 [vitest-global-setup] Creating test users...');
    await createTestUsers();
  }
}

export async function teardown() {
  // Stop the platform
  await testPlatformStop();
}
