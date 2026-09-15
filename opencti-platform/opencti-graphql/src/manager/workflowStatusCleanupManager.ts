import conf, { BUS_TOPICS, ENTITIES_WORKFLOW_FEATURE_FLAG, booleanConf, isFeatureEnabled, logApp } from '../config/conf';
import { internalDeleteElementById } from '../database/middleware';
import { fullEntitiesList, internalLoadById } from '../database/middleware-loader';
import { notify } from '../database/redis';
import { FilterMode, FilterOperator } from '../generated/graphql';
import { lockResources } from '../lock/master-lock';
import { getWorkflowStatusLockKey, isStatusOrphaned } from '../modules/workflow/domain/workflow-domain';
import { ABSTRACT_INTERNAL_OBJECT } from '../schema/general';
import { ENTITY_TYPE_STATUS } from '../schema/internalObject';
import type { BasicWorkflowStatus } from '../types/store';
import { executionContext, WORKFLOW_MANAGER_USER } from '../utils/access';
import { type ManagerDefinition, registerManager } from './managerModule';

const WORKFLOW_STATUS_CLEANUP_MANAGER_ENABLED = booleanConf('workflow_status_cleanup_manager:enabled', true);
const WORKFLOW_STATUS_CLEANUP_MANAGER_KEY = conf.get('workflow_status_cleanup_manager:lock_key') || 'workflow_status_cleanup_manager_lock';
const SCHEDULE_TIME = conf.get('workflow_status_cleanup_manager:interval') || 86400000; // 1 day

/**
 * Hard-deletes `Status` records whose grace period (set by `reconcileOrphanedStatuses` on
 * republish, see workflow-domain.ts) has elapsed. Each candidate is re-verified as still orphaned
 * right before deletion, since state can change during the grace window. Idempotent by
 * construction: re-running the check-then-delete on an already-deleted record is a no-op.
 */
export const workflowStatusCleanupHandler = async () => {
  const context = executionContext('workflow_status_cleanup_manager');
  const candidates = await fullEntitiesList<BasicWorkflowStatus>(context, WORKFLOW_MANAGER_USER, [ENTITY_TYPE_STATUS], {
    filters: {
      mode: FilterMode.And,
      filters: [{ key: ['to_be_deleted_at'], values: [new Date().toISOString()], operator: FilterOperator.Lte }],
      filterGroups: [],
    },
  });

  let errorCount = 0;
  for (let i = 0; i < candidates.length; i += 1) {
    const status = candidates[i];
    // Share a lock with publishWorkflowDefinition so a concurrent republish cannot restore/recreate
    // this Status (clearing its `to_be_deleted_at`) between our earlier list query and the delete
    // below — clearing the mark does not cancel a deletion already in progress, so we must reload
    // the Status and its deadline/usage under the lock, right before deleting.
    const lock = await lockResources([getWorkflowStatusLockKey(status.type)]);
    try {
      const freshStatus = await internalLoadById<BasicWorkflowStatus>(context, WORKFLOW_MANAGER_USER, status.id);
      if (!freshStatus || !freshStatus.to_be_deleted_at || new Date(freshStatus.to_be_deleted_at) > new Date()) {
        // Deletion mark was cleared or deadline pushed back by a republish while we were waiting for the lock.
        continue;
      }
      const stillOrphaned = await isStatusOrphaned(context, WORKFLOW_MANAGER_USER, freshStatus);
      if (stillOrphaned) {
        const { element: deleted } = await internalDeleteElementById(context, WORKFLOW_MANAGER_USER, freshStatus.id, ENTITY_TYPE_STATUS);
        await notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].DELETE_TOPIC, deleted, WORKFLOW_MANAGER_USER);
      }
    } catch (e) {
      logApp.error('[OPENCTI-MODULE] Workflow status cleanup error', { cause: e, manager: 'WORKFLOW_STATUS_CLEANUP_MANAGER', id: status.id, errorCount });
      errorCount += 1;
    } finally {
      await lock.unlock();
    }
  }
  logApp.debug('[OPENCTI-MODULE] Workflow status cleanup manager process complete', { count: candidates.length });
};

const WORKFLOW_STATUS_CLEANUP_MANAGER_DEFINITION: ManagerDefinition = {
  id: 'WORKFLOW_STATUS_CLEANUP_MANAGER',
  label: 'Workflow status cleanup manager',
  executionContext: 'workflow_status_cleanup_manager',
  cronSchedulerHandler: {
    handler: workflowStatusCleanupHandler,
    interval: SCHEDULE_TIME,
    lockKey: WORKFLOW_STATUS_CLEANUP_MANAGER_KEY,
  },
  enabledByConfig: WORKFLOW_STATUS_CLEANUP_MANAGER_ENABLED,
  enabledToStart(): boolean {
    return this.enabledByConfig;
  },
  enabled(): boolean {
    return this.enabledByConfig;
  },
};

if (isFeatureEnabled(ENTITIES_WORKFLOW_FEATURE_FLAG)) {
  registerManager(WORKFLOW_STATUS_CLEANUP_MANAGER_DEFINITION);
}
