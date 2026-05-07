/**
 * Leaf module for async workflow action completion reporting.
 *
 * Design constraints:
 * - This file imports ONLY generic DB primitives (middleware, middleware-loader).
 * - It does NOT import from work.js or workflow-domain.ts to avoid circular dependencies.
 * - work.js and workflow-domain.ts can safely import from here.
 */
import { logApp } from '../../../config/conf';
import { updateAttribute } from '../../../database/middleware';
import { storeLoadById } from '../../../database/middleware-loader';
import type { AuthContext, AuthUser } from '../../../types/user';
import { bypassDraftContext } from '../../../utils/draftContext';
import { ActionRegistry } from '../registry/workflow-actions';
import { ENTITY_TYPE_WORKFLOW_INSTANCE, type AsyncActionSlot, type WorkflowPendingTransition } from '../types/workflow-types';

/**
 * Called when a background task associated with a workflow async action completes.
 * Updates the slot status, and if all slots succeeded, runs syncActions and advances currentState.
 * If a slot failed, sets pendingStatus='error'.
 *
 * This is the single callback point from work.js (via updateWorkTaskToComplete).
 */
export const reportWorkflowAsyncActionResult = async (
  context: AuthContext,
  user: AuthUser,
  workflowInstanceId: string,
  workflowActionId: string,
  status: 'success' | 'failed',
  error?: string,
): Promise<void> => {
  const executionContext = bypassDraftContext(context);
  const executionUser = executionContext.user!;

  const instanceEntity = await storeLoadById<any>(executionContext, executionUser, workflowInstanceId, ENTITY_TYPE_WORKFLOW_INSTANCE);
  if (!instanceEntity) {
    logApp.warn('[workflow-async-completion] WorkflowInstance not found', { workflowInstanceId });
    return;
  }

  let pendingTransition: WorkflowPendingTransition | null = null;
  try {
    pendingTransition = typeof instanceEntity.pendingTransition === 'string'
      ? JSON.parse(instanceEntity.pendingTransition)
      : instanceEntity.pendingTransition ?? null;
  } catch {
    logApp.error('[workflow-async-completion] Failed to parse pendingTransition', { workflowInstanceId });
    return;
  }

  if (!pendingTransition) {
    logApp.warn('[workflow-async-completion] No pendingTransition found on instance', { workflowInstanceId });
    return;
  }

  // Find the matching slot and update its status
  const slotIndex = pendingTransition.asyncActions.findIndex((s) => s.id === workflowActionId);
  if (slotIndex === -1) {
    logApp.warn('[workflow-async-completion] Slot not found in pendingTransition', { workflowInstanceId, workflowActionId });
    return;
  }

  pendingTransition.asyncActions[slotIndex].status = status;

  const allDone = pendingTransition.asyncActions.every((s) => s.status !== 'pending');
  const anyFailed = pendingTransition.asyncActions.some((s) => s.status === 'failed');

  if (!allDone) {
    // Some tasks still running — persist the updated slot and wait
    await updateAttribute(executionContext, executionUser, workflowInstanceId, ENTITY_TYPE_WORKFLOW_INSTANCE, [
      { key: 'pendingTransition', value: [JSON.stringify(pendingTransition)] },
    ]);
    return;
  }

  if (anyFailed) {
    // At least one async task failed — surface the error, keep state unchanged
    await updateAttribute(executionContext, executionUser, workflowInstanceId, ENTITY_TYPE_WORKFLOW_INSTANCE, [
      { key: 'pendingTransition', value: [JSON.stringify(pendingTransition)] },
      { key: 'pendingStatus', value: ['error'] },
      { key: 'pendingError', value: [error ?? 'One or more async workflow actions failed'] },
    ]);
    logApp.warn('[workflow-async-completion] Async actions failed', { workflowInstanceId, error });
    return;
  }

  // All async tasks succeeded — run syncActions (phase 2)
  const workflowContext = {
    user: executionUser,
    entity: { id: instanceEntity.entity_id },
    context: executionContext,
    runtimeParams: pendingTransition.runtimeParams ?? {},
  };

  for (const actionConfig of pendingTransition.syncActions) {
    const actionFn = ActionRegistry[actionConfig.type];
    if (!actionFn) {
      logApp.error('[workflow-async-completion] Unknown syncAction type', { type: actionConfig.type });
      await updateAttribute(executionContext, executionUser, workflowInstanceId, ENTITY_TYPE_WORKFLOW_INSTANCE, [
        { key: 'pendingStatus', value: ['error'] },
        { key: 'pendingError', value: [`Unknown syncAction type: ${actionConfig.type}`] },
      ]);
      return;
    }
    try {
      await actionFn(workflowContext, actionConfig.params);
    } catch (syncError) {
      const syncErrorMsg = syncError instanceof Error ? syncError.message : String(syncError);
      logApp.error('[workflow-async-completion] syncAction failed', { type: actionConfig.type, error: syncErrorMsg });
      await updateAttribute(executionContext, executionUser, workflowInstanceId, ENTITY_TYPE_WORKFLOW_INSTANCE, [
        { key: 'pendingStatus', value: ['error'] },
        { key: 'pendingError', value: [`syncAction '${actionConfig.type}' failed: ${syncErrorMsg}`] },
      ]);
      return;
    }
  }

  // All phases complete — advance state and clear pending
  const history = (() => {
    try { return JSON.parse(instanceEntity.history || '[]'); } catch { return []; }
  })();
  history.push({
    state: pendingTransition.toState,
    user_id: pendingTransition.triggeredBy,
    timestamp: new Date().toISOString(),
    event: pendingTransition.event,
    completedAt: new Date().toISOString(),
  });

  await updateAttribute(executionContext, executionUser, workflowInstanceId, ENTITY_TYPE_WORKFLOW_INSTANCE, [
    { key: 'currentState', value: [pendingTransition.toState] },
    { key: 'history', value: [JSON.stringify(history)] },
    { key: 'pendingStatus', value: [null] },
    { key: 'pendingError', value: [null] },
    { key: 'pendingTransition', value: [null] },
  ]);

  logApp.info('[workflow-async-completion] Transition completed', {
    workflowInstanceId,
    toState: pendingTransition.toState,
    event: pendingTransition.event,
  });
};
