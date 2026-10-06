import { beforeEach, describe, expect, it, vi } from 'vitest';
import { loadEntity, updateAttribute } from '../../../src/database/middleware';
import { storeLoadById } from '../../../src/database/middleware-loader';
import { findByType } from '../../../src/modules/entitySetting/entitySetting-domain';
import { getAllowedTransitions, getWorkflowInstance, triggerWorkflowEvent } from '../../../src/modules/workflow/domain/workflow-domain';
import { reportWorkflowAsyncActionResult } from '../../../src/modules/workflow/domain/workflow-async-completion';
import { ActionRegistry } from '../../../src/modules/workflow/registry/workflow-actions';
import { ENTITY_TYPE_WORKFLOW_INSTANCE } from '../../../src/modules/workflow/types/workflow-types';
import { validateDataBeforeIndexing } from '../../../src/schema/schema-attributes';
import '../../../src/modules/workflow/storage/workflow-instance-entity';

vi.mock('../../../src/database/middleware', () => ({
  createEntity: vi.fn(), createRelation: vi.fn(), deleteElementById: vi.fn(), loadEntity: vi.fn(), updateAttribute: vi.fn(),
}));
vi.mock('../../../src/database/middleware-loader', () => ({
  fullEntitiesList: vi.fn().mockResolvedValue([]), internalLoadById: vi.fn(), storeLoadById: vi.fn(),
}));
vi.mock('../../../src/modules/entitySetting/entitySetting-domain', () => ({ findByType: vi.fn() }));
vi.mock('../../../src/domain/user', () => ({ resolveUserById: vi.fn() }));
vi.mock('../../../src/database/members', () => ({
  loadAssignees: vi.fn().mockResolvedValue([]), loadParticipants: vi.fn().mockResolvedValue([]),
}));
vi.mock('../../../src/modules/notification/notification-domain', () => ({ addNotification: vi.fn() }));
vi.mock('../../../src/manager/telemetryManager', () => ({ addWorkflowPublishCount: vi.fn() }));
vi.mock('../../../src/modules/workflow/registry/workflow-actions', () => ({ ActionRegistry: {} }));
vi.mock('../../../src/utils/draftContext', () => ({ bypassDraftContext: vi.fn((context) => context) }));
vi.mock('../../../src/utils/access', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../src/utils/access')>(),
  validateUserAccessOperation: vi.fn().mockReturnValue(true),
}));

describe('Terminal workflow persistence', () => {
  const user = { id: 'user-id' } as any;
  const context = { user } as any;
  const entity = { id: 'entity-id', internal_id: 'entity-id', entity_type: 'DraftWorkspace' };
  let stored: any;
  let definition: any;
  const validate = vi.fn();
  const onEnter = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
    validate.mockReset();
    onEnter.mockReset();
    ActionRegistry.validateDraft = validate;
    ActionRegistry.terminalTestEnter = onEnter;
    ActionRegistry.terminalTestAsync = vi.fn(async (ctx) => {
      ctx.pendingAsyncSlots?.push({ id: 'slot-id', workId: 'work-id', type: 'terminalTestAsync', status: 'pending' });
    });
    stored = {
      id: 'instance-id', internal_id: 'instance-id', entity_type: ENTITY_TYPE_WORKFLOW_INSTANCE,
      entity_id: entity.id, workflow_id: 'workflow-id', currentState: 'reviewed',
      history: JSON.stringify([{ state: 'reviewed', event: 'Review', user_id: user.id }]),
    };
    definition = {
      initialState: 'initial',
      states: [{ statusId: 'initial' }, { statusId: 'reviewed', onEnter: [{ type: 'terminalTestEnter' }] }],
      transitions: [{ from: 'reviewed', event: 'Validate', syncActions: [{ type: 'validateDraft' }] }],
    };
    vi.mocked(findByType).mockResolvedValue({ id: 'setting-id', workflow_id: 'workflow-id' } as any);
    vi.mocked(loadEntity).mockImplementation(async () => ({ ...stored }));
    vi.mocked(storeLoadById).mockImplementation(async (_ctx, _user, id) => {
      if (id === entity.id) return entity;
      if (id === stored.id) return { ...stored };
      if (id === 'workflow-id') return { id, published_version: { content: JSON.stringify(definition) } };
      return null;
    });
    vi.mocked(updateAttribute).mockImplementation(async (_ctx, _user, _id, type, patches) => {
      expect(type).toBe(ENTITY_TYPE_WORKFLOW_INSTANCE);
      const updated = { ...stored, ...Object.fromEntries(patches.map(({ key, value }) => [key, value?.[0]])) };
      // Exercise the same schema validation that rejects nil mandatory fields before indexing.
      validateDataBeforeIndexing(updated);
      stored = updated;
      return { element: { ...stored } } as any;
    });
  });

  it('keeps the storage schema strict about nil currentState', () => {
    expect(() => validateDataBeforeIndexing({ ...stored, currentState: undefined })).toThrow('mandatory field cannot be nil');
    expect(() => validateDataBeforeIndexing({ ...stored, currentState: null })).toThrow('mandatory field cannot be nil');
  });

  it.each([null, undefined])('persists terminal success with destination %s and prevents replay after reloading', async (to) => {
    definition.transitions[0].to = to;
    expect(await getAllowedTransitions(context, user, entity.id)).toMatchObject([{ event: 'Validate', toState: null }]);

    const result = await triggerWorkflowEvent(context, user, entity.id, 'Validate', 'Approved');

    expect(result).toMatchObject({
      success: true,
      executionStatus: 'completed',
      newState: 'reviewed',
      instance: { id: stored.id, __typename: 'WorkflowInstance', currentState: 'reviewed', allowedTransitions: [] },
    });
    expect(stored).toMatchObject({ currentState: 'reviewed', completed: true });
    expect(JSON.parse(stored.history)).toEqual([
      { state: 'reviewed', event: 'Review', user_id: user.id },
      expect.objectContaining({ state: 'reviewed', event: 'Validate', user_id: user.id, comment: 'Approved', completed: true }),
    ]);
    expect(await getWorkflowInstance(context, user, entity.id)).toMatchObject({ currentState: 'reviewed', allowedTransitions: [] });
    expect(await getAllowedTransitions(context, user, entity.id)).toEqual([]);
    expect(await triggerWorkflowEvent(context, user, entity.id, 'Validate')).toMatchObject({ success: false });
    expect(validate).toHaveBeenCalledOnce();
    expect(onEnter).not.toHaveBeenCalled();
  });

  it('does not complete or persist a terminal transition whose side effect fails', async () => {
    validate.mockRejectedValueOnce(new Error('Validation failed'));
    expect(await triggerWorkflowEvent(context, user, entity.id, 'Validate')).toMatchObject({ success: false, reason: 'Workflow execution failed: Validation failed' });
    expect(stored.currentState).toBe('reviewed');
    expect(stored.completed).toBeUndefined();
    expect(updateAttribute).not.toHaveBeenCalled();
    expect(await getAllowedTransitions(context, user, entity.id)).toHaveLength(1);
  });

  it('retains ordinary ending-status behavior', async () => {
    definition.transitions[0].to = 'done';
    definition.states.push({ statusId: 'done', onEnter: [{ type: 'terminalTestEnter' }] });
    expect(await triggerWorkflowEvent(context, user, entity.id, 'Validate')).toMatchObject({ success: true, newState: 'done' });
    expect(stored.currentState).toBe('done');
    expect(onEnter).toHaveBeenCalledOnce();
    expect(await getAllowedTransitions(context, user, entity.id)).toEqual([]);
  });

  it('does not mistake a self-loop for completion', async () => {
    definition.transitions[0].to = 'reviewed';
    expect(await triggerWorkflowEvent(context, user, entity.id, 'Validate')).toMatchObject({ success: true, newState: 'reviewed' });
    expect(stored.completed).toBeUndefined();
    expect(onEnter).toHaveBeenCalledOnce();
    expect(await getAllowedTransitions(context, user, entity.id)).toHaveLength(1);
  });

  it('keeps a failed async terminal transition incomplete and retryable', async () => {
    definition.transitions[0].asyncActions = [{ type: 'terminalTestAsync' }];
    await triggerWorkflowEvent(context, user, entity.id, 'Validate');
    await reportWorkflowAsyncActionResult(context, user, stored.id, 'slot-id', 'failed', 'Task failed');
    expect(stored).toMatchObject({ currentState: 'reviewed', pendingStatus: 'error', pendingError: 'Task failed' });
    expect(stored.completed).toBeUndefined();
    expect(validate).not.toHaveBeenCalled();
    expect(await getAllowedTransitions(context, user, entity.id)).toHaveLength(1);
  });

  it('preserves terminal intent through asynchronous completion without re-entering the source state', async () => {
    definition.transitions[0].asyncActions = [{ type: 'terminalTestAsync' }];
    expect(await triggerWorkflowEvent(context, user, entity.id, 'Validate')).toMatchObject({ success: true, executionStatus: 'pending' });
    expect(stored.currentState).toBe('reviewed');
    expect(stored.completed).toBeUndefined();
    expect(JSON.parse(stored.pendingTransition)).toMatchObject({ toState: 'reviewed', completesWorkflow: true });
    expect(validate).not.toHaveBeenCalled();

    await reportWorkflowAsyncActionResult(context, user, stored.id, 'slot-id', 'success');

    expect(stored).toMatchObject({ currentState: 'reviewed', completed: true, pendingStatus: null, pendingTransition: null });
    expect(JSON.parse(stored.history).at(-1)).toMatchObject({ state: 'reviewed', event: 'Validate', completed: true });
    expect(await getAllowedTransitions(context, user, entity.id)).toEqual([]);
    expect(onEnter).not.toHaveBeenCalled();
    expect(validate).toHaveBeenCalledOnce();
    await reportWorkflowAsyncActionResult(context, user, stored.id, 'slot-id', 'success');
    expect(validate).toHaveBeenCalledOnce();
  });
});
