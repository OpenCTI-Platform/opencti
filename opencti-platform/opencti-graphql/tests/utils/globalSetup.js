import { platformStart, platformStop } from '../../src/boot';
import { deleteBucket } from '../../src/database/file-storage';
import { deleteQueues } from '../../src/domain/connector';
import { ADMIN_USER, testContext } from './testQuery';
import { elDeleteIndexes, elPlatformIndices } from '../../src/database/engine';
import { wait } from '../../src/database/utils';
import { createRedisClient } from '../../src/database/redis';

const platformClean = async () => {
  // Delete the bucket
  await deleteBucket();
  // Delete all rabbitmq queues
  await deleteQueues(testContext, ADMIN_USER);
  // Remove all elastic indices
  const indices = await elPlatformIndices();
  await elDeleteIndexes(indices.map((i) => i.index));
  // Delete redis streams
  const testRedisClient = createRedisClient('reset');
  await testRedisClient.del('stream.opencti');
  testRedisClient.disconnect();
};

export async function setup() {
  // Platform cleanup before executing tests
  await platformClean();
  // Start the platform
  await platformStart();
  await wait(15000); // Wait 15 secs for complete platform start
}

export async function teardown() {
  // Stop the platform
  await platformStop();
}
