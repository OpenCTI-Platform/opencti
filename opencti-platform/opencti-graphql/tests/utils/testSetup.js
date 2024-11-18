import '../../src/modules/index';
import cacheManager from '../../src/manager/cacheManager';
import { initializeRedisClients } from '../../src/database/redis';
import { searchEngineInit } from '../../src/database/engine';
import { initializeFileStorageClient } from '../../src/database/file-storage';
import { initExclusionListCache } from '../../src/database/exclusionListCacheTree';
import { isFeatureEnabled } from '../../src/config/conf';

await initializeRedisClients();
await searchEngineInit();
await initializeFileStorageClient();
cacheManager.init();
if (isFeatureEnabled('EXCLUSION_LIST')) {
    await initExclusionListCache(null);
}
