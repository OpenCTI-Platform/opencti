import { type ManagerDefinition, registerManager } from './managerModule';
import conf, { booleanConf, isFeatureEnabled, NODE_INSTANCE_ID, logApp } from '../config/conf';
import { redisGetExclusionListStatus } from '../database/redis';
import { executionContext } from '../utils/access';
import { isCacheTreeInitialized, rebuildExclusionListCacheTree } from '../database/exclusionListCacheTree';
import { rebuildExclusionListCacheSlow } from '../database/exclusionListCacheSlow';

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
  const redisCacheStatus = await redisGetExclusionListStatus();
  // cache tree is never initialized at platform init because it is too time consuming, so we build it on the first run of the manager
  // if cache tree is initialized, we only need to rebuild if a change has been applied to exclusion lists
  if (!isCacheTreeInitialized()) {
    logApp.info('[OPENCTI-MODULE][EXCLUSION-BUILD-MANAGER] Cache tree needs to be initialized.');
    await rebuildExclusionListCacheTree(context, redisCacheStatus?.last_refresh_ask_date ?? new Date().toString());
    logApp.info('[OPENCTI-MODULE][EXCLUSION-BUILD-MANAGER] Cache tree initialized.');
  } else if (redisCacheStatus && redisCacheStatus.last_refresh_ask_date
      && (!redisCacheStatus[NODE_INSTANCE_ID] || redisCacheStatus.last_refresh_ask_date !== redisCacheStatus[NODE_INSTANCE_ID])) {
    logApp.info('[OPENCTI-MODULE][EXCLUSION-BUILD-MANAGER] Cache needs to be rebuilt.', { redisCacheStatus });
    await rebuildExclusionListCacheSlow(context, redisCacheStatus.last_refresh_ask_date);
    logApp.info('[OPENCTI-MODULE][EXCLUSION-BUILD-MANAGER] Slow cache has been rebuilt.', { redisCacheStatus });
    await rebuildExclusionListCacheTree(context, redisCacheStatus.last_refresh_ask_date);
    logApp.info('[OPENCTI-MODULE][EXCLUSION-BUILD-MANAGER] All cache have been rebuilt.', { redisCacheStatus });
  }
};

const EXCLUSION_LIST_CACHE_BUILD_MANAGER_DEFINITION: ManagerDefinition = {
  id: 'EXCLUSION_LIST_CACHE_BUILD_MANAGER',
  label: 'Exclusion list cache build manager',
  executionContext: 'exclusion_list_cache_build_manager',
  cronSchedulerHandler: {
    handler: exclusionListCacheBuildHandler,
    interval: SCHEDULE_TIME,
    lockKey: EXCLUSION_LIST_CACHE_BUILD_MANAGER_KEY + NODE_INSTANCE_ID,
  },
  enabledByConfig: EXCLUSION_LIST_CACHE_BUILD_MANAGER_ENABLED,
  enabledToStart(): boolean {
    return this.enabledByConfig;
  },
  enabled(): boolean {
    return this.enabledByConfig;
  }
};

if (isFeatureEnabled('EXCLUSION_LIST')) {
  registerManager(EXCLUSION_LIST_CACHE_BUILD_MANAGER_DEFINITION);
}
