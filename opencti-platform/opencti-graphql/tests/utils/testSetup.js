import { beforeAll, afterAll } from 'vitest';
import cacheManager from '../../src/manager/cacheManager';
import { initializeRedisClients, shutdownRedisClients } from '../../src/database/redis';

beforeAll(async () => {
  initializeRedisClients();
  await cacheManager.start();
});

afterAll(async () => {
  await cacheManager.shutdown();
  await shutdownRedisClients();
});
