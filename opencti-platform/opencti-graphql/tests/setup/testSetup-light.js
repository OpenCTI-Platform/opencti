import '../../src/modules';
import cacheManager from '../../src/manager/cacheManager';
import { initializeRedisClients } from '../../src/database/redis';
import { searchEngineInit } from '../../src/database/engine';
import { logApp } from '../../src/config/conf';

const startTime = new Date().getTime();
await initializeRedisClients();
await searchEngineInit();
cacheManager.init();

logApp.info(`[vitest-test-setup-light][time] init test in ${new Date().getTime() - startTime}`);
