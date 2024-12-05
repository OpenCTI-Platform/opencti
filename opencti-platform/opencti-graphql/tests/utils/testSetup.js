import '../../src/modules/index';
import cacheManager from '../../src/manager/cacheManager';
import { initializeRedisClients } from '../../src/database/redis';
import { searchEngineInit } from '../../src/database/engine';
import { initializeFileStorageClient } from '../../src/database/file-storage';
import { isFeatureEnabled } from '../../src/config/conf';
import { initExclusionListCacheSlow } from '../../src/database/exclusionListCacheSlow';

await initializeRedisClients();
await searchEngineInit();
await initializeFileStorageClient();
cacheManager.init();
if (isFeatureEnabled('EXCLUSION_LIST')) {
  await initExclusionListCacheSlow();
}
