/**
 * Leaf module for async workflow action completion reporting.
 *
 * Design constraints:
 * - This file imports ONLY generic DB primitives (middleware, middleware-loader) plus the
 *   equally-leaf `workflow-projection.ts` (no import chain back to `middleware.ts`).
 * - It does NOT import from work.js or workflow-domain.ts to avoid circular dependencies.
 * - work.js and workflow-domain.ts can safely import from here.
 */
import { logApp } from '../../../config/conf';
import { FunctionalError } from '../../../config/errors';
import { updateAttribute } from '../../../database/middleware';
import { storeLoadById } from '../../../database/middleware-loader';
import type { AuthContext, AuthUser } from '../../../types/user';
import { bypassDraftContext } from '../../../utils/draftContext';
import { WORKFLOW_MANAGER_USER } from '../../../utils/access';
import { lockResources } from '../../../lock/master-lock';
import { ActionRegistry } from '../registry/workflow-actions';
import { ENTITY_TYPE_WORKFLOW_INSTANCE, type AsyncActionSlot, type Context, type WorkflowPendingTransition } from '../types/workflow-types';
import { projectWorkflowState, resolveProjectionScope } from './workflow-projection';

// history is rewritten as a whole on each append, so keep only the latest entries.
const MAX_WORKFLOW_HISTORY_ENTRIES = 200;
export const appendWorkflowHistoryEntry = (history: any[], entry: any): any[] => {
  return [...history, entry].slice(-MAX_WORKFLOW_HISTORY_ENTRIES);
};

export const runWorkflowBypassActions = async (workflowContext: Context, pendingTransition: WorkflowPendingTransition): Promise<void> => {
  const slots: AsyncActionSlot[] = [];
  workflowContext.pendingAsyncSlots = slots;
  workflowContext.__asyncActionSlots = slots;
  while (pendingTransition.syncActions.length > 0) {
    const action = pendingTransition.syncActions[0];
    const actionFn = ActionRegistry[action.type];
    if (!actionFn) throw new Error(`Unknown workflow action type: ${action.type}`);
    await actionFn(workflowContext, typeof action.params === 'string' ? JSON.parse(action.params) : action.params);
    pendingTransition.syncActions.shift();
    if (slots.length > 0) {
      pendingTransition.asyncActions = slots.map(({ id, workId, type, status }) => ({ id, workId, type, status }));
      return;
    }
  }
  pendingTransition.asyncActions = [];
};

/**
 * Called when a background task associated with a workflow async action completes.
 * Updates the slot status, and if all slots succeeded, runs syncActions and advances currentState.
 * If a slot failed, sets pendingStatus='error'.
 *
 * This is the single callback point from work.js (via updateWorkTaskToComplete).
 */
const completeWorkflowAsyncActionResult = async (
  context: AuthContext,
  user: AuthUser,
  workflowInstanceId: string,
  workflowActionId: string,
  status: 'success' | 'failed',
  error?: string,
): Promise<void> => {
  const executionContext = bypassDraftContext(context);
  // Use the explicitly-passed `user`, not `context.user`: some callers (e.g. work.js via
  // `executionContext(source)`) build a context with no `.user` and thread the identity separately.
  const executionUser: AuthUser = { ...user, draft_context: undefined };

  const instanceEntity = await storeLoadById<any>(executionContext, executionUser, workflowInstanceId, ENTITY_TYPE_WORKFLOW_INSTANCE);
  if (!instanceEntity) {
    logApp.warn('[workflow-async-completion] WorkflowInstance not found', { workflowInstanceId });
    return;
  }

  let pendingTransition: WorkflowPendingTransition | null;
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

  if (pendingTransition.event === 'event_bypass' && instanceEntity.pendingStatus !== 'pending') return;

  // Find the matching slot and update its status
  const slotIndex = pendingTransition.asyncActions.findIndex((s) => s.id === workflowActionId);
  if (slotIndex === -1) {
    logApp.warn('[workflow-async-completion] Slot not found in pendingTransition', { workflowInstanceId, workflowActionId });
    return;
  }

  if (pendingTransition.event === 'event_bypass' && pendingTransition.asyncActions[slotIndex].status !== 'pending') return;

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
  // Load the full target entity so dynamic resolvers (AUTHOR, CREATORS, etc.) have the data they need.
  // Fall back to a minimal stub if the load fails (e.g. entity deleted during the async window or transient DB error).
  const fullEntity = await storeLoadById<any>(executionContext, executionUser, instanceEntity.entity_id, 'Basic-Object')
    .catch((err) => {
      logApp.warn('[workflow-async-completion] Failed to load full entity, falling back to stub', { entityId: instanceEntity.entity_id, error: err });
      return null;
    });
  const workflowContext = {
    user: executionUser,
    entity: fullEntity ?? { id: instanceEntity.entity_id },
    context: executionContext,
    runtimeParams: pendingTransition.runtimeParams ?? {},
  };

  if (pendingTransition.event === 'event_bypass') {
    try {
      if (!fullEntity) throw new Error('Entity not found during workflow bypass completion');
      const { createListTask } = await import('../../../domain/backgroundTask-common');
      await runWorkflowBypassActions({
        ...workflowContext,
        user: WORKFLOW_MANAGER_USER,
        __createListTask: createListTask,
        __workflowInstanceId: workflowInstanceId,
        __draftEntityIds: pendingTransition.draftEntityIds ?? [],
      }, pendingTransition);
      if (pendingTransition.asyncActions.length > 0) {
        await updateAttribute(executionContext, executionUser, workflowInstanceId, ENTITY_TYPE_WORKFLOW_INSTANCE, [
          { key: 'pendingTransition', value: [JSON.stringify(pendingTransition)] },
        ]);
        return;
      }
    } catch (bypassError) {
      await updateAttribute(executionContext, executionUser, workflowInstanceId, ENTITY_TYPE_WORKFLOW_INSTANCE, [
        { key: 'pendingTransition', value: [JSON.stringify(pendingTransition)] },
        { key: 'pendingStatus', value: ['error'] },
        { key: 'pendingError', value: [bypassError instanceof Error ? bypassError.message : String(bypassError)] },
      ]);
      return;
    }
  }

  for (const actionConfig of pendingTransition.syncActions) {
    const actionFn = ActionRegistry[actionConfig.type];
    if (!actionFn) {
      logApp.error('[workflow-async-completion] Unknown syncAction type', { type: actionConfig.type });
      await updateAttribute(executionContext, executionUser, workflowInstanceId, ENTITY_TYPE_WORKFLOW_INSTANCE, [
        { key: 'pendingTransition', value: [JSON.stringify(pendingTransition)] },
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
        { key: 'pendingTransition', value: [JSON.stringify(pendingTransition)] },
        { key: 'pendingStatus', value: ['error'] },
        { key: 'pendingError', value: [`syncAction '${actionConfig.type}' failed: ${syncErrorMsg}`] },
      ]);
      return;
    }
  }

  // Run onEnter actions of the target state (phase 2 equivalent of engine's onEnter block)
  for (const actionConfig of (pendingTransition.onEnterActions ?? [])) {
    const actionFn = ActionRegistry[actionConfig.type];
    if (!actionFn) {
      logApp.error('[workflow-async-completion] Unknown onEnter action type', { type: actionConfig.type });
      await updateAttribute(executionContext, executionUser, workflowInstanceId, ENTITY_TYPE_WORKFLOW_INSTANCE, [
        { key: 'pendingTransition', value: [JSON.stringify(pendingTransition)] },
        { key: 'pendingStatus', value: ['error'] },
        { key: 'pendingError', value: [`Unknown onEnter action type: ${actionConfig.type}`] },
      ]);
      return;
    }
    try {
      await actionFn(workflowContext, actionConfig.params);
    } catch (onEnterError) {
      const onEnterErrorMsg = onEnterError instanceof Error ? onEnterError.message : String(onEnterError);
      logApp.error('[workflow-async-completion] onEnter action failed', { type: actionConfig.type, error: onEnterErrorMsg });
      await updateAttribute(executionContext, executionUser, workflowInstanceId, ENTITY_TYPE_WORKFLOW_INSTANCE, [
        { key: 'pendingTransition', value: [JSON.stringify(pendingTransition)] },
        { key: 'pendingStatus', value: ['error'] },
        { key: 'pendingError', value: [`onEnter action '${actionConfig.type}' failed: ${onEnterErrorMsg}`] },
      ]);
      return;
    }
  }

  // All phases complete — advance state and clear pending
  const previousHistory = (() => {
    try {
      return JSON.parse(instanceEntity.history || '[]');
    } catch {
      return [];
    }
  })();
  const history = appendWorkflowHistoryEntry(previousHistory, {
    state: pendingTransition.toState,
    user_id: pendingTransition.triggeredBy,
    timestamp: new Date().toISOString(),
    event: pendingTransition.event,
    completedAt: new Date().toISOString(),
    ...(pendingTransition.comment ? { comment: pendingTransition.comment } : {}),
  });

  await updateAttribute(executionContext, executionUser, workflowInstanceId, ENTITY_TYPE_WORKFLOW_INSTANCE, [
    { key: 'currentState', value: [pendingTransition.toState] },
    { key: 'history', value: [JSON.stringify(history)] },
    { key: 'pendingStatus', value: [null] },
    { key: 'pendingError', value: [null] },
    { key: 'pendingTransition', value: [null] },
  ]);

  // Keep the legacy `x_opencti_workflow_id` in sync with the completed state.
  // `projectWorkflowState` never throws (best-effort, logs and skips on failure).
  if (fullEntity) {
    await projectWorkflowState(executionContext, executionUser, fullEntity, pendingTransition.toState, resolveProjectionScope(instanceEntity.scope));
  } else {
    logApp.warn('[workflow-async-completion] Skipping status projection: entity could not be loaded', { entityId: instanceEntity.entity_id });
  }

  logApp.info('[workflow-async-completion] Transition completed', {
    workflowInstanceId,
    toState: pendingTransition.toState,
    event: pendingTransition.event,
  });
};

export const reportWorkflowAsyncActionResult = async (
  context: AuthContext,
  user: AuthUser,
  workflowInstanceId: string,
  workflowActionId: string,
  status: 'success' | 'failed',
  error?: string,
): Promise<void> => {
  // Any non-'pending' value would mark the slot as done, so only accept the two terminal statuses.
  if (status !== 'success' && status !== 'failed') {
    throw FunctionalError('Invalid workflow async action status', { status });
  }
  const instance = await storeLoadById<any>(bypassDraftContext(context), { ...user, draft_context: undefined }, workflowInstanceId, ENTITY_TYPE_WORKFLOW_INSTANCE);
  if (!instance) {
    logApp.warn('[workflow-async-completion] WorkflowInstance not found', { workflowInstanceId });
    return;
  }
  // Unbounded retries on purpose: the background task can finish while the initiating mutation still
  // holds this lock (before its async slots are registered). A bounded window would drop the callback
  // and leave the instance pending forever. A dead holder's lock still expires after max_ttl.
  const lock = await lockResources([`workflow-mutation-${instance.entity_id}`], { retryCount: -1 });
  try {
    await completeWorkflowAsyncActionResult(context, user, workflowInstanceId, workflowActionId, status, error);
  } finally {
    await lock.unlock();
  }
};
