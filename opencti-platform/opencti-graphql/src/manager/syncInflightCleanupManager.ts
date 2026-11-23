import type { _Object } from '@aws-sdk/client-s3';
import { type ManagerDefinition, registerManager } from './managerModule';
import conf, { booleanConf, ENABLED_SYNC_MANAGER_FILE_REFERENCE_MODE, logApp } from '../config/conf';
import { deleteFileFromStorage, rawListObjects } from '../database/raw-file-storage';
import { SYNC_INFLIGHT_STORAGE_PATH } from '../modules/internal/document/document-types';

// Not set in default.json, so it follows file reference mode unless set explicitly to drain staged files after turning the mode off.
const SYNC_INFLIGHT_CLEANUP_MANAGER_ENABLED = booleanConf('sync_inflight_cleanup_manager:enabled', ENABLED_SYNC_MANAGER_FILE_REFERENCE_MODE);
const SYNC_INFLIGHT_CLEANUP_MANAGER_KEY = conf.get('sync_inflight_cleanup_manager:lock_key') || 'sync_inflight_cleanup_manager_lock';
const SCHEDULE_TIME = conf.get('sync_inflight_cleanup_manager:interval') || 3600000; // 1 hour
const INFLIGHT_TTL_MS = conf.get('sync_inflight_cleanup_manager:ttl') ?? 604800000; // 1 week

interface KeyedStorageObject extends _Object {
  Key: string;
}

interface CleanupFailureLog {
  error_name: string;
  manager: string;
}

const isExpiredStagedObject = (object: _Object, cutoff: number): object is KeyedStorageObject => {
  const lastModified = object.LastModified?.getTime();
  return object.Key !== undefined && lastModified !== undefined && lastModified < cutoff;
};

const deleteStagedObject = async (key: string) => {
  try {
    await deleteFileFromStorage(key);
    return true;
  } catch (err) {
    const errorName = err instanceof Error ? err.name : typeof err;
    const failure: CleanupFailureLog = { error_name: errorName, manager: 'SYNC_INFLIGHT_CLEANUP_MANAGER' };
    logApp.warn('[OPENCTI-MODULE] Sync inflight cleanup manager failed to delete a staged file', failure);
    return false;
  }
};

const deleteExpiredObjects = async (objects: _Object[], cutoff: number): Promise<number> => {
  const expiredObjects = objects.filter((object): object is KeyedStorageObject => isExpiredStagedObject(object, cutoff));
  let deletedCount = 0;
  for (let i = 0; i < expiredObjects.length; i += 1) {
    const isDeleted = await deleteStagedObject(expiredObjects[i].Key);
    if (isDeleted) {
      deletedCount += 1;
    }
  }
  return deletedCount;
};

export const syncInflightCleanupHandler = async () => {
  const prefix = `${SYNC_INFLIGHT_STORAGE_PATH}/`;
  const cutoff = Date.now() - INFLIGHT_TTL_MS;
  let deletedCount = 0;
  let truncated = true;
  let continuationToken: string | undefined;
  while (truncated) {
    const response = await rawListObjects(prefix, true, continuationToken);
    deletedCount += await deleteExpiredObjects(response.Contents ?? [], cutoff);
    truncated = response.IsTruncated ?? false;
    continuationToken = response.NextContinuationToken;
  }
  if (deletedCount > 0) {
    logApp.info(`[OPENCTI-MODULE] Sync inflight cleanup manager deleted ${deletedCount} staged file(s)`);
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
  enabledByConfig: SYNC_INFLIGHT_CLEANUP_MANAGER_ENABLED,
  enabledToStart(): boolean {
    return this.enabledByConfig;
  },
  enabled(): boolean {
    return this.enabledByConfig;
  },
};

registerManager(SYNC_INFLIGHT_CLEANUP_MANAGER_DEFINITION);
