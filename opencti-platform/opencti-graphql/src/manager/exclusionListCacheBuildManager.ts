import { type ManagerDefinition, registerManager } from './managerModule';
import conf, { booleanConf, logApp } from '../config/conf';
import { redisGetExclusionListStatus } from '../database/redis';
import { executionContext } from '../utils/access';
import { rebuildExclusionListCache } from '../database/exclusionListCache';

const EXCLUSION_LIST_CACHE_BUILD_MANAGER_ENABLED = booleanConf('exclusion_list_cache_build_manager:enabled', true);
const EXCLUSION_LIST_CACHE_BUILD_MANAGER_KEY = conf.get('exclusion_list_cache_build_manager:lock_key') || 'exclusion_list_cache_build_manager_lock';
const SCHEDULE_TIME = conf.get('exclusion_list_cache_build_manager:interval') || 10000; // 10 seconds

/**
 * Look at most recent cache refresh ask date in redis
 *  if they differ or if status is not initialized, cache needs to be rebuilt and pushed to local cache and redis cache key
 *  otherwise, do nothing
 */
export const exclusionListCacheBuildHandler = async () => {
  const context = executionContext('exclusion_list_cache_build_manager');
  const { last_refresh_ask_date, last_cache_date } = await redisGetExclusionListStatus();
  if (!last_cache_date || (last_refresh_ask_date && last_refresh_ask_date !== last_cache_date)) {
    logApp.info('[OPENCTI-MODULE][EXCLUSION-BUILD-MANAGER] Cache needs to be rebuilt.', { last_refresh_ask_date, last_cache_date });
    await rebuildExclusionListCache(context, last_refresh_ask_date ?? (new Date()).toString());
    logApp.info('[OPENCTI-MODULE][EXCLUSION-BUILD-MANAGER] Cache has been rebuilt.', { last_refresh_ask_date, last_cache_date });
  }
};

const EXCLUSION_LIST_CACHE_BUILD_MANAGER_DEFINITION: ManagerDefinition = {
  id: 'EXCLUSION_LIST_CACHE_BUILD_MANAGER',
  label: 'Exclusion list cache build manager',
  executionContext: 'exclusion_list_cache_build_manager',
  cronSchedulerHandler: {
    handler: exclusionListCacheBuildHandler,
    interval: SCHEDULE_TIME,
    lockKey: EXCLUSION_LIST_CACHE_BUILD_MANAGER_KEY,
  },
  enabledByConfig: EXCLUSION_LIST_CACHE_BUILD_MANAGER_ENABLED,
  enabledToStart(): boolean {
    return this.enabledByConfig;
  },
  enabled(): boolean {
    return this.enabledByConfig;
  }
};

registerManager(EXCLUSION_LIST_CACHE_BUILD_MANAGER_DEFINITION);
