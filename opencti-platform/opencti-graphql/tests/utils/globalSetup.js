import { platformStart, platformStop } from '../../src/boot';
import { deleteBucket } from '../../src/database/file-storage';
import { deleteQueues } from '../../src/domain/connector';
import { ADMIN_USER, testContext } from './testQuery';
import { elDeleteIndexes } from '../../src/database/engine';
import { wait, WRITE_PLATFORM_INDICES } from '../../src/database/utils';
import { ELASTIC_CREATION_PATTERN } from '../../src/config/conf';
import { createRedisClient } from '../../src/database/redis';

const platformClean = async () => {
  console.log('[VITEST] Cleaning platform');
  // Delete the bucket
  await deleteBucket();
  // Delete all rabbitmq queues
  await deleteQueues(testContext, ADMIN_USER);
  // Remove all elastic indices
  await elDeleteIndexes(WRITE_PLATFORM_INDICES.map((id) => `${id}${ELASTIC_CREATION_PATTERN}`));
  // Delete redis streams
  const testRedisClient = createRedisClient('reset');
  await testRedisClient.del('stream.opencti');
  testRedisClient.disconnect();
};

export async function setup() {
  // Platform cleanup before executing tests
  await platformClean();
  // Start the platform
  console.log('[VITEST] Starting platform');
  await platformStart();
  await wait(15000); // Wait 15 secs for complete platform start
}

export async function teardown() {
  console.log('[VITEST] Stopping platform');
  // Stop the platform
  await platformStop();
}
