import { type ManagerDefinition, registerManager } from './managerModule';
import conf, { booleanConf, logApp } from '../config/conf';
import { GARBAGE_COLLECTION_MANAGER_USER, executionContext } from '../utils/access';
import { confirmDelete, findOldDeleteOperations } from '../modules/deleteOperation/deleteOperation-domain';

const GARBAGE_COLLECTION_MANAGER_ENABLED = booleanConf('garbage_collection_manager:enabled', true);
const TRASH_ENABLED = booleanConf('app:trash:enabled', true);
const GARBAGE_COLLECTION_MANAGER_KEY = conf.get('garbage_collection_manager:lock_key') || 'garbage_collection_manager_lock';
const SCHEDULE_TIME = conf.get('garbage_collection_manager:interval') || 60000; // 1 minute
const BATCH_SIZE = conf.get('garbage_collection_manager:batch_size') || 10000;
const DELETED_RETENTION_DAYS = conf.get('garbage_collection_manager:deleted_retention_days') || 7;

/**
 * Search for N (batch_size) older than DELETED_RETENTION_DAYS DeleteOperations
 * Completely delete these deleteOperations
 */
export const garbageCollectionHandler = async () => {
  const context = executionContext('garbage_collection_manager');
  const deletedRetentionDaysToConsider = Math.max(DELETED_RETENTION_DAYS, 1);
  const deleteOperationsToManage = await findOldDeleteOperations(context, GARBAGE_COLLECTION_MANAGER_USER, deletedRetentionDaysToConsider, BATCH_SIZE);
  let errorCount = 0;
  for (let i = 0; i < deleteOperationsToManage.length; i += 1) {
    try {
      const deleteOperation = deleteOperationsToManage[i];
      await confirmDelete(context, GARBAGE_COLLECTION_MANAGER_USER, deleteOperation.id);
    } catch (e) {
      logApp.error('[OPENCTI-MODULE] Garbage collection delete error', { cause: e, manager: 'GARBAGE_MANAGER', id: deleteOperationsToManage[i].id, errorCount });
      errorCount += 1;
    }
  }
  logApp.debug('[OPENCTI-MODULE] Garbage collection manager deletion process complete', { count: deleteOperationsToManage.length });
};

const GARBAGE_COLLECTION_MANAGER_DEFINITION: ManagerDefinition = {
  id: 'GARBAGE_COLLECTION_MANAGER',
  label: 'Garbage collection manager',
  executionContext: 'garbage_collection_manager',
  cronSchedulerHandler: {
    handler: garbageCollectionHandler,
    interval: SCHEDULE_TIME,
    lockKey: GARBAGE_COLLECTION_MANAGER_KEY,
  },
  enabledByConfig: TRASH_ENABLED && GARBAGE_COLLECTION_MANAGER_ENABLED,
  enabledToStart(): boolean {
    return this.enabledByConfig;
  },
  enabled(): boolean {
    return this.enabledByConfig;
  }
};

registerManager(GARBAGE_COLLECTION_MANAGER_DEFINITION);
