import { type ManagerDefinition, registerManager } from './managerModule';
import conf, { isFeatureEnabled, logApp, PLATFORM_INSTANCE_ID } from '../config/conf';
import { redisGetExclusionListStatus } from '../database/redis';
import { getIsCacheInitialized, syncExclusionListCache } from '../database/exclusionListCache';

const EXCLUSION_LIST_CACHE_SYNC_MANAGER_LOCK_KEY = conf.get('exclusion_list_cache_sync_manager:lock_key') || 'exclusion_list_cache_sync_manager_lock';
const SCHEDULE_TIME = conf.get('exclusion_list_cache_sync_manager:interval') || 10000; // 10 seconds

const exclusionListCacheSyncHandler = async () => {
  const exclusionListStatus = await redisGetExclusionListStatus();
  const isLocalCacheInitialized = getIsCacheInitialized();

  if (!exclusionListStatus?.last_cache_date) return;

  if (exclusionListStatus.last_cache_date !== exclusionListStatus[PLATFORM_INSTANCE_ID] || !isLocalCacheInitialized) {
    logApp.info('[OPENCTI-MODULE][EXCLUSION-SYNC-MANAGER] local cache needs to be updated');
    await syncExclusionListCache(exclusionListStatus.last_cache_date);
    logApp.info('[OPENCTI-MODULE][EXCLUSION-SYNC-MANAGER] local cache has been updated');
  }
};

const EXCLUSION_LIST_CACHE_SYNC_MANAGER: ManagerDefinition = {
  id: 'EXCLUSION_LIST_CACHE_SYNC_MANAGER',
  label: 'Exclusion list cache sync manager',
  executionContext: 'exclusion_list_cache_sync_manager',
  cronSchedulerHandler: {
    handler: exclusionListCacheSyncHandler,
    interval: SCHEDULE_TIME,
    lockKey: EXCLUSION_LIST_CACHE_SYNC_MANAGER_LOCK_KEY
  },
  enabledByConfig: true,
  enabledToStart(): boolean {
    return this.enabledByConfig;
  },
  enabled(): boolean {
    return this.enabledByConfig;
  }
};
if (isFeatureEnabled('EXCLUSION_LIST')) {
  registerManager(EXCLUSION_LIST_CACHE_SYNC_MANAGER);
}
