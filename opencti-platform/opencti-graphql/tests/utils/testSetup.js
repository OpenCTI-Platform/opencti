import '../../src/modules/index';
import cacheManager from '../../src/manager/cacheManager';
import { initializeRedisClients } from '../../src/database/redis';
import { searchEngineInit } from '../../src/database/engine';
import { initializeFileStorageClient } from '../../src/database/raw-file-storage';
import { initExclusionListCache } from '../../src/database/exclusionListCache';
import { initLockFork } from '../../src/lock/master-lock';
import { logApp } from '../../src/config/conf';

const startTime = new Date().getTime();
await initializeRedisClients();
await searchEngineInit();
await initializeFileStorageClient();
cacheManager.init();
await initExclusionListCache();
initLockFork();

logApp.info(`[vitest-test-setup][time] init test in ${new Date().getTime() - startTime}`);
