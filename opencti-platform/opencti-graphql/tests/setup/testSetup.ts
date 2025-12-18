import '../../src/modules/index';
import cacheManager from '../../src/manager/cacheManager';
import { initializeRedisClients } from '../../src/database/redis';
import { searchEngineInit } from '../../src/database/engine';
import { initializeFileStorageClient } from '../../src/database/raw-file-storage';
import { initExclusionListCache } from '../../src/database/exclusionListCache';
import { initLockFork } from '../../src/lock/master-lock';
import { logApp } from '../../src/config/conf';
import { beforeAll } from 'vitest';

cacheManager.init();

beforeAll(async () => {
  const startTime = new Date().getTime();
  await initializeRedisClients();
  logApp.info(`[vitest-test-setup][time] initializeRedisClients in ${new Date().getTime() - startTime}`);
  await searchEngineInit();
  logApp.info(`[vitest-test-setup][time] searchEngineInit in ${new Date().getTime() - startTime}`);
  await initializeFileStorageClient();
  logApp.info(`[vitest-test-setup][time] initializeFileStorageClient in ${new Date().getTime() - startTime}`);
  await initExclusionListCache();
  logApp.info(`[vitest-test-setup][time] initExclusionListCache in ${new Date().getTime() - startTime}`);
  initLockFork();
  logApp.info(`[vitest-test-setup][time] initLockFork in ${new Date().getTime() - startTime}`);
});
