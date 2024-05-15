import '../../src/modules/index';
import cacheManager from '../../src/manager/cacheManager';
import { initializeRedisClients } from '../../src/database/redis';
import { searchEngineInit } from '../../src/database/engine';
import { initializeFileStorageClient } from '../../src/database/file-storage';

await initializeRedisClients();
await searchEngineInit();
await initializeFileStorageClient();
cacheManager.init();
