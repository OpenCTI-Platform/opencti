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

const testPlatformStart = async () => {
  const context = executionContext('platform_test_initialization');
  logApp.info('[OPENCTI] Starting platform');
  try {
    // Check all dependencies access
    await searchEngineInit();
    // Init the cache manager
    await cacheManager.start();
    // Init the platform default
    await initializeInternalQueues();
    await initializeBucket();
    await initializeSchema();
    await initializeData(context, true);
    await initializeAdminUser(context);
    await initDefaultNotifiers(context);
    // Init the modules
    await startModules();
  } catch (e) {
    logApp.error(e);
    process.exit(1);
  }
};
const testPlatformStop = async () => {
  const stopTime = new Date().getTime();
  // Shutdown the cache manager
  await cacheManager.shutdown();
  // Destroy the modules
  await shutdownModules();
  // Shutdown the redis clients
  await shutdownRedisClients();
  logApp.info(`[OPENCTI] Platform stopped ${new Date().getTime() - stopTime} ms`);
};

const platformClean = async () => {
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
};

export async function setup() {
  // Platform cleanup before executing tests
  await platformClean();
  // Start the platform
  await testPlatformStart();
  await wait(15000); // Wait 15 secs for complete platform start
  await createTestUsers();
}

export async function teardown() {
  // Stop the platform
  await testPlatformStop();
}
