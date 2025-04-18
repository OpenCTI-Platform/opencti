import '../../src/modules/index';
import cacheManager from '../../src/manager/cacheManager';
import { initializeRedisClients } from '../../src/database/redis';
import { searchEngineInit } from '../../src/database/engine';
import { initializeFileStorageClient } from '../../src/database/file-storage';
import { initExclusionListCache } from '../../src/database/exclusionListCache';

/**
 * This is run before every test file.
 */
await initializeRedisClients();
await searchEngineInit();
await initializeFileStorageClient();
cacheManager.init();
await initExclusionListCache();
// initLockFork();
