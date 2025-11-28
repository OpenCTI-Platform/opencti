import '../../src/modules';
import cacheManager from '../../src/manager/cacheManager';
import { initializeRedisClients } from '../../src/database/redis';
import { searchEngineInit } from '../../src/database/engine';
import { initializeFileStorageClient } from '../../src/database/raw-file-storage';
import { initExclusionListCache } from '../../src/database/exclusionListCache';
import { initLockFork } from '../../src/lock/master-lock';

// To be removed when typescript es2022
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
// await initializeRedisClients();

// To be removed when typescript es2022
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
// await searchEngineInit();

// To be removed when typescript es2022
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
// await initializeFileStorageClient();
cacheManager.init();

// To be removed when typescript es2022
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
// await initExclusionListCache();
// initLockFork();
