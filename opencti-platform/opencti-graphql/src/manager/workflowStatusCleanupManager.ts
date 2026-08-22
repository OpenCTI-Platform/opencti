import conf, { booleanConf, logApp } from '../config/conf';
import { internalDeleteElementById } from '../database/middleware';
import { fullEntitiesList } from '../database/middleware-loader';
import { FilterMode, FilterOperator } from '../generated/graphql';
import { isStatusOrphaned } from '../modules/workflow/domain/workflow-domain';
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
    try {
      const stillOrphaned = await isStatusOrphaned(context, WORKFLOW_MANAGER_USER, status);
      if (stillOrphaned) {
        await internalDeleteElementById(context, WORKFLOW_MANAGER_USER, status.id, ENTITY_TYPE_STATUS);
      }
    } catch (e) {
      logApp.error('[OPENCTI-MODULE] Workflow status cleanup error', { cause: e, manager: 'WORKFLOW_STATUS_CLEANUP_MANAGER', id: status.id, errorCount });
      errorCount += 1;
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

registerManager(WORKFLOW_STATUS_CLEANUP_MANAGER_DEFINITION);
