// First, as modules/index was: the schema files must be evaluated before conf.js, which reaches them through
// vocabulary-types. Evaluated during conf.js, attribute-definition reads TEST_MODE as undefined.
import { registerModules } from '../../src/composition-root';
import cacheManager from '../../src/manager/cacheManager';
import { initializeRedisClients } from '../../src/database/redis';
import { searchEngineInit } from '../../src/database/engine';
import { initializeFileStorageClient } from '../../src/database/raw-file-storage';
import { initExclusionListCache } from '../../src/database/exclusionListCache';
import { initLockFork } from '../../src/lock/master-lock';
import { logApp } from '../../src/config/conf';
import { registerLocalStrategy } from '../../src/modules/authenticationProvider/provider-local';

// Before any test file is imported: tests/utils/testQueryHelper builds the graphql schema at import time
registerModules();

const startTime = new Date().getTime();
await initializeRedisClients();
await searchEngineInit();
await initializeFileStorageClient();
await registerLocalStrategy();
cacheManager.init();
await initExclusionListCache();
initLockFork();

logApp.info(`[vitest-test-setup][time] init test in ${new Date().getTime() - startTime}`);
