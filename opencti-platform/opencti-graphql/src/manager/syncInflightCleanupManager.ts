import { type ManagerDefinition, registerManager } from './managerModule';
import conf, { booleanConf, ENABLED_SYNC_MANAGER_FILE_REFERENCE_MODE, logApp } from '../config/conf';
import { deleteFileFromStorage, rawListObjects } from '../database/raw-file-storage';
import { SYNC_INFLIGHT_STORAGE_PATH } from '../modules/internal/document/document-types';

const SYNC_INFLIGHT_CLEANUP_MANAGER_ENABLED = booleanConf('sync_inflight_cleanup_manager:enabled', true);
const SYNC_INFLIGHT_CLEANUP_MANAGER_KEY = conf.get('sync_inflight_cleanup_manager:lock_key') || 'sync_inflight_cleanup_manager_lock';
const SCHEDULE_TIME = conf.get('sync_inflight_cleanup_manager:interval') || 3600000; // 1 hour
const INFLIGHT_TTL_MS = conf.get('sync_inflight_cleanup_manager:ttl') || 86400000; // 24 hours

/**
 * Backstop only: copyFileFromSyncReference deletes its own sync/inflight/ key right after a
 * successful copy, so this should rarely find anything. Only exists to sweep crashed/abandoned
 * transfers. These keys are never indexed in ES, so this lists raw S3 keys directly.
 */
export const syncInflightCleanupHandler = async () => {
  const prefix = `${SYNC_INFLIGHT_STORAGE_PATH}/`;
  const cutoff = Date.now() - INFLIGHT_TTL_MS;
  let deletedCount = 0;
  let truncated = true;
  let continuationToken;
  while (truncated) {
    const response = await rawListObjects(prefix, true, continuationToken);
    const contents = response.Contents ?? [];
    for (let i = 0; i < contents.length; i += 1) {
      const object = contents[i];
      if (object.Key && object.LastModified && object.LastModified.getTime() < cutoff) {
        try {
          await deleteFileFromStorage(object.Key);
          deletedCount += 1;
        } catch (err) {
          logApp.error('[OPENCTI-MODULE] Sync inflight cleanup manager error', { cause: err, manager: 'SYNC_INFLIGHT_CLEANUP_MANAGER', key: object.Key });
        }
      }
    }
    truncated = response.IsTruncated ?? false;
    continuationToken = response.NextContinuationToken;
  }
  if (deletedCount > 0) {
    logApp.info(`[OPENCTI-MODULE] Sync inflight cleanup manager deleted ${deletedCount} orphaned file(s)`);
  }
};

const SYNC_INFLIGHT_CLEANUP_MANAGER_DEFINITION: ManagerDefinition = {
  id: 'SYNC_INFLIGHT_CLEANUP_MANAGER',
  label: 'Sync inflight cleanup manager',
  executionContext: 'sync_inflight_cleanup_manager',
  cronSchedulerHandler: {
    handler: syncInflightCleanupHandler,
    interval: SCHEDULE_TIME,
    lockKey: SYNC_INFLIGHT_CLEANUP_MANAGER_KEY,
  },
  // Only relevant once ref-mode transfers can actually happen; no point sweeping an S3
  // prefix that will always be empty when the feature it backstops is disabled.
  enabledByConfig: SYNC_INFLIGHT_CLEANUP_MANAGER_ENABLED && ENABLED_SYNC_MANAGER_FILE_REFERENCE_MODE,
  enabledToStart(): boolean {
    return this.enabledByConfig;
  },
  enabled(): boolean {
    return this.enabledByConfig;
  },
};

registerManager(SYNC_INFLIGHT_CLEANUP_MANAGER_DEFINITION);
