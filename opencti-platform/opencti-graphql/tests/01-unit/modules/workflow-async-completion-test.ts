import { beforeEach, describe, expect, it, vi } from 'vitest';
import { logApp } from '../../../src/config/conf';
import { appendWorkflowHistoryEntry, reportWorkflowAsyncActionResult } from '../../../src/modules/workflow/domain/workflow-async-completion';
import { projectWorkflowState } from '../../../src/modules/workflow/domain/workflow-projection';
import { updateAttribute } from '../../../src/database/middleware';
import { storeLoadById } from '../../../src/database/middleware-loader';
import { ActionRegistry } from '../../../src/modules/workflow/registry/workflow-actions';
import { createListTask } from '../../../src/domain/backgroundTask-common';
import { lockResources } from '../../../src/lock/master-lock';

vi.mock('../../../src/domain/backgroundTask-common', () => ({ createListTask: vi.fn() }));
vi.mock('../../../src/utils/access', () => ({ WORKFLOW_MANAGER_USER: { id: 'workflow-manager' } }));
vi.mock('../../../src/lock/master-lock', () => ({ lockResources: vi.fn().mockResolvedValue({ unlock: vi.fn() }) }));

vi.mock('../../../src/database/middleware', () => ({
  updateAttribute: vi.fn(),
}));

vi.mock('../../../src/database/middleware-loader', () => ({
  storeLoadById: vi.fn(),
}));

vi.mock('../../../src/utils/draftContext', () => ({
  bypassDraftContext: vi.fn((context) => ({ ...context, user: context.user })),
}));

vi.mock('../../../src/config/conf', () => ({
  logApp: { info: vi.fn(), error: vi.fn(), warn: vi.fn() },
}));

// ActionRegistry is mocked at module level so individual tests can override entries
vi.mock('../../../src/modules/workflow/registry/workflow-actions', () => ({
  ActionRegistry: {},
}));

vi.mock('../../../src/modules/workflow/domain/workflow-projection', () => ({
  projectWorkflowState: vi.fn(),
  resolveProjectionScope: vi.fn((scope: string | undefined) => (scope && scope !== 'standard' ? scope : 'GLOBAL')),
}));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
const mockContext = { user: { id: 'ctx-user-id' } } as any;
const mockUser = { id: 'user-id' } as any;
const contextWithoutUser = {} as any;

const makeInstance = (overrides: Record<string, unknown> = {}) => ({
  id: 'instance-id',
  internal_id: 'instance-id',
  entity_id: 'entity-id',
  currentState: 'draft',
  history: '[]',
  pendingStatus: 'pending',
  pendingError: null,
  pendingTransition: null,
  ...overrides,
});

const makePendingTransition = (overrides: Record<string, unknown> = {}) => ({
  event: 'submit',
  toState: 'reviewing',
  triggeredBy: 'user-id',
  triggeredAt: new Date().toISOString(),
  runtimeParams: {},
  asyncActions: [
    { id: 'slot-1', workId: 'work-1', type: 'asyncBulkAction', status: 'pending' },
  ],
  syncActions: [],
  ...overrides,
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('reportWorkflowAsyncActionResult', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(lockResources).mockResolvedValue({ unlock: vi.fn() });
  });

  it('rejects a status other than success / failed without touching the instance', async () => {
    vi.mocked(storeLoadById).mockResolvedValue(makeInstance({ pendingTransition: JSON.stringify(makePendingTransition({ event: 'event_bypass' })) }) as any);

    await expect(reportWorkflowAsyncActionResult(mockContext, mockUser, 'instance-id', 'slot-1', 'done' as any)).rejects.toThrow('Invalid workflow async action status');

    expect(lockResources).not.toHaveBeenCalled();
    expect(updateAttribute).not.toHaveBeenCalled();
  });

  it.each(['event_bypass', 'submit', null])('waits beyond bounded lock retries and reloads registered slots after initial event %s', async (event) => {
    const registered = makeInstance({ pendingTransition: JSON.stringify(makePendingTransition({ event: event ?? 'event_bypass' })) });
    const beforeRegistration = makeInstance({ pendingTransition: event ? JSON.stringify(makePendingTransition({ event, asyncActions: [] })) : null });
    let locked = false;
    const unlock = vi.fn();
    vi.mocked(storeLoadById).mockImplementation(async (_context, _user, id) => {
      if (id === 'instance-id') return structuredClone(locked ? registered : beforeRegistration) as any;
      return { id: 'entity-id', internal_id: 'entity-id', entity_type: 'Incident' } as any;
    });
    vi.mocked(lockResources).mockImplementation(async (_ids, options?: { retryCount?: number }) => {
      if (options?.retryCount !== -1) throw new Error('lock retry window exhausted');
      locked = true;
      return { unlock } as any;
    });

    await expect(reportWorkflowAsyncActionResult(mockContext, mockUser, 'instance-id', 'slot-1', 'success')).resolves.toBeUndefined();

    expect(lockResources).toHaveBeenCalledWith(['workflow-mutation-entity-id'], { retryCount: -1 });
    expect(updateAttribute).toHaveBeenCalledWith(expect.anything(), expect.anything(), 'instance-id', expect.anything(), expect.arrayContaining([
      { key: 'currentState', value: ['reviewing'] },
      { key: 'pendingTransition', value: [null] },
    ]));
    expect(unlock).toHaveBeenCalledOnce();
  });

  it('resumes bypass hooks through repeated async phases without replay and projects with the explicit user', async () => {
    const entity = { id: 'entity-id', internal_id: 'entity-id', entity_type: 'DraftWorkspace' };
    const pending = makePendingTransition({
      event: 'event_bypass',
      comment: 'override',
      runtimeParams: { shareOrganizationIds: ['org-id'] },
      draftEntityIds: ['draft-object'],
      syncActions: [{ type: 'bypassSync', params: '{"message":"exit remainder"}' }, { type: 'bypassAsync' }, { type: 'bypassSync', params: { message: 'enter remainder' } }],
    });
    const instance = makeInstance({ pendingTransition: JSON.stringify(pending) });
    vi.mocked(storeLoadById).mockImplementation(async (_context, _user, id) => (id === 'instance-id' ? instance : entity) as any);
    vi.mocked(updateAttribute).mockImplementation(async (_context, _user, _id, _type, patches) => {
      for (const patch of patches) (instance as any)[patch.key] = patch.value[0];
      return { element: instance } as any;
    });
    ActionRegistry.bypassSync = vi.fn();
    ActionRegistry.bypassAsync = vi.fn(async (executionContext) => {
      expect(executionContext).toMatchObject({ user: { id: 'workflow-manager' }, runtimeParams: pending.runtimeParams, __workflowInstanceId: 'instance-id', __draftEntityIds: ['draft-object'], __createListTask: createListTask });
      executionContext.pendingAsyncSlots!.push({ id: 'slot-2', workId: 'work-2', type: 'asyncBulkAction', status: 'pending' });
    });

    await reportWorkflowAsyncActionResult(contextWithoutUser, mockUser, 'instance-id', 'slot-1', 'success');
    expect(instance.currentState).toBe('draft');
    expect(instance.pendingStatus).toBe('pending');
    expect(projectWorkflowState).not.toHaveBeenCalled();
    expect(ActionRegistry.bypassSync).toHaveBeenCalledTimes(1);
    expect(ActionRegistry.bypassSync).toHaveBeenCalledWith(expect.anything(), { message: 'exit remainder' });
    expect(JSON.parse(instance.pendingTransition!).syncActions).toEqual([{ type: 'bypassSync', params: { message: 'enter remainder' } }]);

    await reportWorkflowAsyncActionResult(contextWithoutUser, mockUser, 'instance-id', 'slot-1', 'success');
    expect(ActionRegistry.bypassAsync).toHaveBeenCalledTimes(1);
    await reportWorkflowAsyncActionResult(contextWithoutUser, mockUser, 'instance-id', 'slot-2', 'success');
    expect(instance.currentState).toBe('reviewing');
    expect(instance.pendingTransition).toBeNull();
    expect(ActionRegistry.bypassSync).toHaveBeenCalledTimes(2);
    expect(JSON.parse(instance.history)).toEqual([expect.objectContaining({ event: 'event_bypass', user_id: 'user-id', comment: 'override', state: 'reviewing' })]);
    expect(projectWorkflowState).toHaveBeenCalledWith({}, { ...mockUser, draft_context: undefined }, entity, 'reviewing', 'GLOBAL');
    await reportWorkflowAsyncActionResult(contextWithoutUser, mockUser, 'instance-id', 'slot-2', 'success');
    expect(ActionRegistry.bypassSync).toHaveBeenCalledTimes(2);
  });

  it.each(['async', 'hook', 'missing-entity'])('surfaces bypass %s completion failure without advancing or replaying', async (failure) => {
    const pending = makePendingTransition({ event: 'event_bypass', syncActions: [{ type: 'bypassFailure' }] });
    const instance = makeInstance({ pendingTransition: JSON.stringify(pending) });
    vi.mocked(storeLoadById).mockImplementation(async (_context, _user, id) => {
      if (id === 'instance-id') return instance as any;
      return failure === 'missing-entity' ? null : { id: 'entity-id' } as any;
    });
    vi.mocked(updateAttribute).mockImplementation(async (_context, _user, _id, _type, patches) => {
      for (const patch of patches) (instance as any)[patch.key] = patch.value[0];
      return { element: instance } as any;
    });
    ActionRegistry.bypassFailure = vi.fn().mockRejectedValue(new Error('hook failed'));
    await reportWorkflowAsyncActionResult(contextWithoutUser, mockUser, 'instance-id', 'slot-1', failure === 'async' ? 'failed' : 'success', 'task failed');
    expect(instance.pendingStatus).toBe('error');
    expect(instance.currentState).toBe('draft');
    expect(instance.pendingError).toBeTruthy();
    expect(projectWorkflowState).not.toHaveBeenCalled();
    expect(ActionRegistry.bypassFailure).toHaveBeenCalledTimes(failure === 'hook' ? 1 : 0);
    await reportWorkflowAsyncActionResult(contextWithoutUser, mockUser, 'instance-id', 'slot-1', 'success');
    expect(ActionRegistry.bypassFailure).toHaveBeenCalledTimes(failure === 'hook' ? 1 : 0);
    expect(instance.pendingStatus).toBe('error');
  });

  it('serializes duplicate bypass completion callbacks so remaining hooks run once', async () => {
    const instance = makeInstance({ pendingTransition: JSON.stringify(makePendingTransition({ event: 'event_bypass', syncActions: [{ type: 'bypassOnce' }] })) });
    let previous = Promise.resolve();
    vi.mocked(lockResources).mockImplementation(async () => {
      const waiting = previous;
      let release!: () => void;
      previous = new Promise<void>((resolve) => {
        release = resolve;
      });
      await waiting;
      return { unlock: release } as any;
    });
    vi.mocked(storeLoadById).mockImplementation(async (_context, _user, id) => structuredClone(id === 'instance-id' ? instance : { id: 'entity-id' }) as any);
    vi.mocked(updateAttribute).mockImplementation(async (_context, _user, _id, _type, patches) => {
      for (const patch of patches) (instance as any)[patch.key] = patch.value[0];
      return { element: instance } as any;
    });
    ActionRegistry.bypassOnce = vi.fn();
    await Promise.all([
      reportWorkflowAsyncActionResult(contextWithoutUser, mockUser, 'instance-id', 'slot-1', 'success'),
      reportWorkflowAsyncActionResult(contextWithoutUser, mockUser, 'instance-id', 'slot-1', 'success'),
    ]);
    expect(ActionRegistry.bypassOnce).toHaveBeenCalledTimes(1);
    expect(JSON.parse(instance.history)).toHaveLength(1);
    expect(lockResources).toHaveBeenCalledWith(['workflow-mutation-entity-id'], { retryCount: -1 });
  });

  it('runs under the explicitly-passed user, even when the context carries no user', async () => {
    (storeLoadById as any).mockResolvedValue(null);

    await reportWorkflowAsyncActionResult({ user: undefined } as any, mockUser, 'instance-id', 'slot-1', 'success');

    expect(storeLoadById).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ id: mockUser.id }), 'instance-id', expect.anything());
  });

  it('returns early when workflow instance is not found', async () => {
    (storeLoadById as any).mockResolvedValue(null);

    await reportWorkflowAsyncActionResult(mockContext, mockUser, 'instance-id', 'slot-1', 'success');

    expect(updateAttribute).not.toHaveBeenCalled();
  });

  it('returns early when pendingTransition JSON is malformed', async () => {
    (storeLoadById as any).mockResolvedValue(
      makeInstance({ pendingTransition: '{ malformed json' }),
    );

    await reportWorkflowAsyncActionResult(mockContext, mockUser, 'instance-id', 'slot-1', 'success');

    expect(updateAttribute).not.toHaveBeenCalled();
  });

  it('returns early when pendingTransition is null', async () => {
    (storeLoadById as any).mockResolvedValue(makeInstance({ pendingTransition: null }));

    await reportWorkflowAsyncActionResult(mockContext, mockUser, 'instance-id', 'slot-1', 'success');

    expect(updateAttribute).not.toHaveBeenCalled();
  });

  it('returns early when the matching slot is not found', async () => {
    const pt = makePendingTransition();
    (storeLoadById as any).mockResolvedValue(
      makeInstance({ pendingTransition: JSON.stringify(pt) }),
    );

    await reportWorkflowAsyncActionResult(mockContext, mockUser, 'instance-id', 'non-existent-slot', 'success');

    expect(updateAttribute).not.toHaveBeenCalled();
  });

  it('persists updated slot and returns without advancing state when other slots are still pending', async () => {
    const pt = makePendingTransition({
      asyncActions: [
        { id: 'slot-1', workId: 'work-1', type: 'asyncBulkAction', status: 'pending' },
        { id: 'slot-2', workId: 'work-2', type: 'asyncBulkAction', status: 'pending' },
      ],
    });
    (storeLoadById as any).mockResolvedValue(
      makeInstance({ pendingTransition: JSON.stringify(pt) }),
    );
    (updateAttribute as any).mockResolvedValue({});

    await reportWorkflowAsyncActionResult(mockContext, mockUser, 'instance-id', 'slot-1', 'success');

    // Only one updateAttribute call, only for the slot update (not state advance)
    expect(updateAttribute).toHaveBeenCalledTimes(1);
    const [, , , , patches] = (updateAttribute as any).mock.calls[0];
    expect(patches).toHaveLength(1);
    expect(patches[0].key).toBe('pendingTransition');
    // State should NOT be advanced
    const ptUpdated = JSON.parse(patches[0].value[0]);
    expect(ptUpdated.asyncActions[0].status).toBe('success');
    expect(ptUpdated.asyncActions[1].status).toBe('pending');
  });

  it('sets pendingStatus=error when all slots have finished but at least one failed', async () => {
    const pt = makePendingTransition({
      asyncActions: [
        { id: 'slot-1', workId: 'work-1', type: 'asyncBulkAction', status: 'pending' },
      ],
    });
    (storeLoadById as any).mockResolvedValue(
      makeInstance({ pendingTransition: JSON.stringify(pt) }),
    );
    (updateAttribute as any).mockResolvedValue({});

    await reportWorkflowAsyncActionResult(mockContext, mockUser, 'instance-id', 'slot-1', 'failed', 'task error');

    expect(updateAttribute).toHaveBeenCalledTimes(1);
    const [, , , , patches] = (updateAttribute as any).mock.calls[0];
    const pendingStatusPatch = patches.find((p: any) => p.key === 'pendingStatus');
    const pendingErrorPatch = patches.find((p: any) => p.key === 'pendingError');
    expect(pendingStatusPatch?.value[0]).toBe('error');
    expect(pendingErrorPatch?.value[0]).toBe('task error');
  });

  it('sets pendingStatus=error when a mix of success and failed slots all finish', async () => {
    const pt = makePendingTransition({
      asyncActions: [
        { id: 'slot-1', workId: 'work-1', type: 'asyncBulkAction', status: 'success' },
        { id: 'slot-2', workId: 'work-2', type: 'asyncBulkAction', status: 'pending' },
      ],
    });
    (storeLoadById as any).mockResolvedValue(
      makeInstance({ pendingTransition: JSON.stringify(pt) }),
    );
    (updateAttribute as any).mockResolvedValue({});

    await reportWorkflowAsyncActionResult(mockContext, mockUser, 'instance-id', 'slot-2', 'failed', 'partial failure');

    const [, , , , patches] = (updateAttribute as any).mock.calls[0];
    expect(patches.find((p: any) => p.key === 'pendingStatus')?.value[0]).toBe('error');
    expect(patches.find((p: any) => p.key === 'pendingError')?.value[0]).toBe('partial failure');
  });

  it('uses default error message when no error string is provided for a failed slot', async () => {
    const pt = makePendingTransition({
      asyncActions: [
        { id: 'slot-1', workId: 'work-1', type: 'asyncBulkAction', status: 'pending' },
      ],
    });
    (storeLoadById as any).mockResolvedValue(
      makeInstance({ pendingTransition: JSON.stringify(pt) }),
    );
    (updateAttribute as any).mockResolvedValue({});

    await reportWorkflowAsyncActionResult(mockContext, mockUser, 'instance-id', 'slot-1', 'failed');

    const [, , , , patches] = (updateAttribute as any).mock.calls[0];
    const pendingErrorPatch = patches.find((p: any) => p.key === 'pendingError');
    expect(pendingErrorPatch?.value[0]).toBe('One or more async workflow actions failed');
  });

  it('sets pendingStatus=error with message when an unknown syncAction type is encountered', async () => {
    const pt = makePendingTransition({
      asyncActions: [
        { id: 'slot-1', workId: 'work-1', type: 'asyncBulkAction', status: 'pending' },
      ],
      syncActions: [{ type: 'unknownActionType', params: {} }],
    });
    (storeLoadById as any).mockResolvedValue(
      makeInstance({ pendingTransition: JSON.stringify(pt) }),
    );
    (ActionRegistry as any).unknownActionType = undefined;
    (updateAttribute as any).mockResolvedValue({});

    await reportWorkflowAsyncActionResult(mockContext, mockUser, 'instance-id', 'slot-1', 'success');

    const calls = (updateAttribute as any).mock.calls;
    // Last updateAttribute call should set error
    const lastPatches = calls[calls.length - 1][4];
    expect(lastPatches.find((p: any) => p.key === 'pendingStatus')?.value[0]).toBe('error');
    expect(lastPatches.find((p: any) => p.key === 'pendingError')?.value[0]).toContain('Unknown syncAction type');
  });

  it('sets pendingStatus=error when a syncAction throws', async () => {
    const pt = makePendingTransition({
      asyncActions: [
        { id: 'slot-1', workId: 'work-1', type: 'asyncBulkAction', status: 'pending' },
      ],
      syncActions: [{ type: 'throwingAction', params: {} }],
    });
    (storeLoadById as any).mockResolvedValue(
      makeInstance({ pendingTransition: JSON.stringify(pt) }),
    );
    (ActionRegistry as any).throwingAction = vi.fn().mockRejectedValue(new Error('sync action blew up'));
    (updateAttribute as any).mockResolvedValue({});

    await reportWorkflowAsyncActionResult(mockContext, mockUser, 'instance-id', 'slot-1', 'success');

    const calls = (updateAttribute as any).mock.calls;
    const lastPatches = calls[calls.length - 1][4];
    expect(lastPatches.find((p: any) => p.key === 'pendingStatus')?.value[0]).toBe('error');
    expect(lastPatches.find((p: any) => p.key === 'pendingError')?.value[0]).toContain('sync action blew up');
  });

  it('advances currentState and clears pendingTransition when all slots succeed and no syncActions', async () => {
    const pt = makePendingTransition({
      asyncActions: [
        { id: 'slot-1', workId: 'work-1', type: 'asyncBulkAction', status: 'pending' },
      ],
      syncActions: [],
    });
    (storeLoadById as any).mockResolvedValue(
      makeInstance({ pendingTransition: JSON.stringify(pt) }),
    );
    (updateAttribute as any).mockResolvedValue({});

    await reportWorkflowAsyncActionResult(mockContext, mockUser, 'instance-id', 'slot-1', 'success');

    expect(updateAttribute).toHaveBeenCalledTimes(1);
    const [, , , , patches] = (updateAttribute as any).mock.calls[0];
    expect(patches.find((p: any) => p.key === 'currentState')?.value[0]).toBe('reviewing');
    expect(patches.find((p: any) => p.key === 'pendingStatus')?.value[0]).toBeNull();
    expect(patches.find((p: any) => p.key === 'pendingTransition')?.value[0]).toBeNull();
    expect(patches.find((p: any) => p.key === 'pendingError')?.value[0]).toBeNull();
  });

  it('runs syncActions in order and then advances state when all slots succeed', async () => {
    const calls: string[] = [];
    const pt = makePendingTransition({
      asyncActions: [
        { id: 'slot-1', workId: 'work-1', type: 'asyncBulkAction', status: 'pending' },
      ],
      syncActions: [
        { type: 'actionA', params: { x: 1 } },
        { type: 'actionB', params: {} },
      ],
    });
    (storeLoadById as any).mockResolvedValue(
      makeInstance({ pendingTransition: JSON.stringify(pt) }),
    );
    (ActionRegistry as any).actionA = vi.fn().mockImplementation(() => {
      calls.push('A');
    });
    (ActionRegistry as any).actionB = vi.fn().mockImplementation(() => {
      calls.push('B');
    });
    (updateAttribute as any).mockResolvedValue({});

    await reportWorkflowAsyncActionResult(mockContext, mockUser, 'instance-id', 'slot-1', 'success');

    expect(calls).toEqual(['A', 'B']);
    const [, , , , patches] = (updateAttribute as any).mock.calls[0];
    expect(patches.find((p: any) => p.key === 'currentState')?.value[0]).toBe('reviewing');
    // History should contain a new entry for the completed transition
    const history = JSON.parse(patches.find((p: any) => p.key === 'history')?.value[0] ?? '[]');
    expect(history.length).toBeGreaterThan(0);
    expect(history[history.length - 1].event).toBe('submit');
    expect(history[history.length - 1].state).toBe('reviewing');
  });

  it('sets pendingStatus=error and persists pendingTransition when an unknown onEnter action type is encountered', async () => {
    const pt = makePendingTransition({
      asyncActions: [
        { id: 'slot-1', workId: 'work-1', type: 'asyncBulkAction', status: 'pending' },
      ],
      syncActions: [],
      onEnterActions: [{ type: 'unknownOnEnterType', params: {} }],
    });
    (storeLoadById as any).mockResolvedValue(
      makeInstance({ pendingTransition: JSON.stringify(pt) }),
    );
    (ActionRegistry as any).unknownOnEnterType = undefined;
    (updateAttribute as any).mockResolvedValue({});

    await reportWorkflowAsyncActionResult(mockContext, mockUser, 'instance-id', 'slot-1', 'success');

    const calls = (updateAttribute as any).mock.calls;
    const lastPatches = calls[calls.length - 1][4];
    expect(lastPatches.find((p: any) => p.key === 'pendingStatus')?.value[0]).toBe('error');
    expect(lastPatches.find((p: any) => p.key === 'pendingError')?.value[0]).toContain('Unknown onEnter action type');
    // pendingTransition must be persisted so the UI shows the correct slot statuses
    const ptPatch = lastPatches.find((p: any) => p.key === 'pendingTransition');
    expect(ptPatch).toBeDefined();
    const ptPersisted = JSON.parse(ptPatch.value[0]);
    expect(ptPersisted.asyncActions[0].status).toBe('success');
  });

  it('sets pendingStatus=error and persists pendingTransition when an onEnter action throws', async () => {
    const pt = makePendingTransition({
      asyncActions: [
        { id: 'slot-1', workId: 'work-1', type: 'asyncBulkAction', status: 'pending' },
      ],
      syncActions: [],
      onEnterActions: [{ type: 'throwingOnEnter', params: {} }],
    });
    (storeLoadById as any).mockResolvedValue(
      makeInstance({ pendingTransition: JSON.stringify(pt) }),
    );
    (ActionRegistry as any).throwingOnEnter = vi.fn().mockRejectedValue(new Error('onEnter blew up'));
    (updateAttribute as any).mockResolvedValue({});

    await reportWorkflowAsyncActionResult(mockContext, mockUser, 'instance-id', 'slot-1', 'success');

    const calls = (updateAttribute as any).mock.calls;
    const lastPatches = calls[calls.length - 1][4];
    expect(lastPatches.find((p: any) => p.key === 'pendingStatus')?.value[0]).toBe('error');
    expect(lastPatches.find((p: any) => p.key === 'pendingError')?.value[0]).toContain('onEnter blew up');
    const ptPatch = lastPatches.find((p: any) => p.key === 'pendingTransition');
    expect(ptPatch).toBeDefined();
    const ptPersisted = JSON.parse(ptPatch.value[0]);
    expect(ptPersisted.asyncActions[0].status).toBe('success');
  });

  it('runs onEnterActions after syncActions and then advances state', async () => {
    const executionOrder: string[] = [];
    const pt = makePendingTransition({
      asyncActions: [
        { id: 'slot-1', workId: 'work-1', type: 'asyncBulkAction', status: 'pending' },
      ],
      syncActions: [{ type: 'syncFirst', params: {} }],
      onEnterActions: [{ type: 'onEnterSecond', params: {} }],
    });
    (storeLoadById as any).mockResolvedValue(
      makeInstance({ pendingTransition: JSON.stringify(pt) }),
    );
    (ActionRegistry as any).syncFirst = vi.fn().mockImplementation(() => {
      executionOrder.push('sync');
    });
    (ActionRegistry as any).onEnterSecond = vi.fn().mockImplementation(() => {
      executionOrder.push('onEnter');
    });
    (updateAttribute as any).mockResolvedValue({});

    await reportWorkflowAsyncActionResult(mockContext, mockUser, 'instance-id', 'slot-1', 'success');

    // syncActions must run before onEnterActions
    expect(executionOrder).toEqual(['sync', 'onEnter']);
    const [, , , , patches] = (updateAttribute as any).mock.calls[0];
    expect(patches.find((p: any) => p.key === 'currentState')?.value[0]).toBe('reviewing');
    expect(patches.find((p: any) => p.key === 'pendingTransition')?.value[0]).toBeNull();
    expect(patches.find((p: any) => p.key === 'pendingStatus')?.value[0]).toBeNull();
  });

  it('advances state when all slots succeed and onEnterActions all succeed', async () => {
    const pt = makePendingTransition({
      asyncActions: [
        { id: 'slot-1', workId: 'work-1', type: 'asyncBulkAction', status: 'pending' },
      ],
      syncActions: [],
      onEnterActions: [{ type: 'onEnterOk', params: { flag: true } }],
    });
    (storeLoadById as any).mockResolvedValue(
      makeInstance({ pendingTransition: JSON.stringify(pt) }),
    );
    (ActionRegistry as any).onEnterOk = vi.fn().mockResolvedValue(undefined);
    (updateAttribute as any).mockResolvedValue({});

    await reportWorkflowAsyncActionResult(mockContext, mockUser, 'instance-id', 'slot-1', 'success');

    expect((ActionRegistry as any).onEnterOk).toHaveBeenCalledTimes(1);
    expect(updateAttribute).toHaveBeenCalledTimes(1);
    const [, , , , patches] = (updateAttribute as any).mock.calls[0];
    expect(patches.find((p: any) => p.key === 'currentState')?.value[0]).toBe('reviewing');
    expect(patches.find((p: any) => p.key === 'pendingTransition')?.value[0]).toBeNull();
  });

  it('accepts a pendingTransition stored as a JSON object (not a string)', async () => {
    const pt = makePendingTransition({
      asyncActions: [
        { id: 'slot-1', workId: 'work-1', type: 'asyncBulkAction', status: 'pending' },
      ],
    });
    // pendingTransition stored already parsed (not a string)
    (storeLoadById as any).mockResolvedValue(makeInstance({ pendingTransition: pt }));
    (updateAttribute as any).mockResolvedValue({});

    await reportWorkflowAsyncActionResult(mockContext, mockUser, 'instance-id', 'slot-1', 'success');

    expect(updateAttribute).toHaveBeenCalledTimes(1);
    const [, , , , patches] = (updateAttribute as any).mock.calls[0];
    expect(patches.find((p: any) => p.key === 'currentState')?.value[0]).toBe('reviewing');
  });

  // ---------------------------------------------------------------------------
  // Full entity loading (fix for "Draft author org" not resolved in onEnterActions)
  // ---------------------------------------------------------------------------

  describe('full entity loading for workflowContext', () => {
    it('passes the full entity (with all relations) to onEnterActions', async () => {
      const fullEntity = {
        id: 'entity-id',
        internal_id: 'entity-id',
        entity_type: 'DraftWorkspace',
        createdBy: 'org-author-id',
        creator_id: 'creator-id',
      };
      const pt = makePendingTransition({
        asyncActions: [
          { id: 'slot-1', workId: 'work-1', type: 'asyncBulkAction', status: 'pending' },
        ],
        syncActions: [],
        onEnterActions: [{ type: 'captureEntityAction', params: {} }],
      });
      const instance = makeInstance({ pendingTransition: JSON.stringify(pt) });

      (storeLoadById as any)
        .mockResolvedValueOnce(instance)
        .mockResolvedValueOnce(instance)
        .mockResolvedValueOnce(fullEntity);

      let capturedEntity: any;
      (ActionRegistry as any).captureEntityAction = vi.fn().mockImplementation((ctx: any) => {
        capturedEntity = ctx.entity;
      });
      (updateAttribute as any).mockResolvedValue({});

      await reportWorkflowAsyncActionResult(mockContext, mockUser, 'instance-id', 'slot-1', 'success');

      // The action must receive the full entity, not just { id }
      expect(capturedEntity).toEqual(fullEntity);
      expect(capturedEntity['createdBy']).toBe('org-author-id');
      expect(capturedEntity.creator_id).toBe('creator-id');
    });

    it('passes the full entity (with all relations) to syncActions', async () => {
      const fullEntity = {
        id: 'entity-id',
        internal_id: 'entity-id',
        entity_type: 'DraftWorkspace',
        createdBy: 'org-author-id',
      };
      const pt = makePendingTransition({
        asyncActions: [
          { id: 'slot-1', workId: 'work-1', type: 'asyncBulkAction', status: 'pending' },
        ],
        syncActions: [{ type: 'captureSyncEntity', params: {} }],
        onEnterActions: [],
      });
      const instance = makeInstance({ pendingTransition: JSON.stringify(pt) });

      (storeLoadById as any)
        .mockResolvedValueOnce(instance)
        .mockResolvedValueOnce(instance)
        .mockResolvedValueOnce(fullEntity);

      let capturedEntity: any;
      (ActionRegistry as any).captureSyncEntity = vi.fn().mockImplementation((ctx: any) => {
        capturedEntity = ctx.entity;
      });
      (updateAttribute as any).mockResolvedValue({});

      await reportWorkflowAsyncActionResult(mockContext, mockUser, 'instance-id', 'slot-1', 'success');

      expect(capturedEntity).toEqual(fullEntity);
      expect(capturedEntity['createdBy']).toBe('org-author-id');
    });

    it('falls back to { id } when the full target entity cannot be found (e.g. deleted during async window)', async () => {
      const pt = makePendingTransition({
        asyncActions: [
          { id: 'slot-1', workId: 'work-1', type: 'asyncBulkAction', status: 'pending' },
        ],
        syncActions: [],
        onEnterActions: [{ type: 'captureFallbackEntity', params: {} }],
      });
      const instance = makeInstance({ pendingTransition: JSON.stringify(pt) });

      (storeLoadById as any)
        .mockResolvedValueOnce(instance)
        .mockResolvedValueOnce(instance)
        .mockResolvedValueOnce(null);

      let capturedEntity: any;
      (ActionRegistry as any).captureFallbackEntity = vi.fn().mockImplementation((ctx: any) => {
        capturedEntity = ctx.entity;
      });
      (updateAttribute as any).mockResolvedValue({});

      await reportWorkflowAsyncActionResult(mockContext, mockUser, 'instance-id', 'slot-1', 'success');

      // Should fall back to minimal stub so the rest of the pipeline can still proceed
      expect(capturedEntity).toEqual({ id: 'entity-id' });
    });

    it('falls back to { id } and logs a warning when storeLoadById throws (e.g. transient DB error)', async () => {
      const pt = makePendingTransition({
        asyncActions: [
          { id: 'slot-1', workId: 'work-1', type: 'asyncBulkAction', status: 'pending' },
        ],
        syncActions: [],
        onEnterActions: [{ type: 'captureErrorFallbackEntity', params: {} }],
      });
      const instance = makeInstance({ pendingTransition: JSON.stringify(pt) });

      (storeLoadById as any)
        .mockResolvedValueOnce(instance)
        .mockResolvedValueOnce(instance)
        .mockRejectedValueOnce(new Error('DB connection lost'));

      let capturedEntity: any;
      (ActionRegistry as any).captureErrorFallbackEntity = vi.fn().mockImplementation((ctx: any) => {
        capturedEntity = ctx.entity;
      });
      (updateAttribute as any).mockResolvedValue({});

      const { logApp } = await import('../../../src/config/conf');

      await reportWorkflowAsyncActionResult(mockContext, mockUser, 'instance-id', 'slot-1', 'success');

      // Should still proceed with the minimal stub
      expect(capturedEntity).toEqual({ id: 'entity-id' });
      // And the error should be logged
      expect((logApp.warn as any)).toHaveBeenCalledWith(
        expect.stringContaining('Failed to load full entity'),
        expect.objectContaining({ entityId: 'entity-id' }),
      );
    });

    it('loads the full entity by entity_id after reloading the instance under lock', async () => {
      const pt = makePendingTransition({
        asyncActions: [{ id: 'slot-1', workId: 'work-1', type: 'asyncBulkAction', status: 'pending' }],
        syncActions: [],
        onEnterActions: [],
      });
      const instance = makeInstance({ pendingTransition: JSON.stringify(pt) });
      const fullEntity = { id: 'entity-id', entity_type: 'DraftWorkspace' };

      (storeLoadById as any)
        .mockResolvedValueOnce(instance)
        .mockResolvedValueOnce(instance)
        .mockResolvedValueOnce(fullEntity);
      (updateAttribute as any).mockResolvedValue({});

      await reportWorkflowAsyncActionResult(mockContext, mockUser, 'instance-id', 'slot-1', 'success');

      expect(storeLoadById).toHaveBeenCalledTimes(3);
      expect(vi.mocked(storeLoadById).mock.calls[1][2]).toBe('instance-id');
      expect(vi.mocked(storeLoadById).mock.calls[2][2]).toBe('entity-id');
      expect(vi.mocked(storeLoadById).mock.calls[2][3]).toBe('Basic-Object');
    });

    // Regression test for #16843: updateAuthorizedMembers running as an onEnterAction must
    // receive an entity that carries RELATION_CREATED_BY so the AUTHOR dynamic member resolves.
    it('passes RELATION_CREATED_BY on the entity to updateAuthorizedMembers in onEnterActions (AUTHOR resolution)', async () => {
      const RELATION_CREATED_BY = 'createdBy';
      const fullEntity = {
        id: 'entity-id',
        entity_type: 'DraftWorkspace',
        [RELATION_CREATED_BY]: 'org-author-id',
      };
      const pt = makePendingTransition({
        asyncActions: [{ id: 'slot-1', workId: 'work-1', type: 'asyncBulkAction', status: 'pending' }],
        syncActions: [],
        onEnterActions: [{ type: 'updateAuthorizedMembers', params: { members: [{ id: 'AUTHOR', access_right: 'edit' }] } }],
      });
      const instance = makeInstance({ pendingTransition: JSON.stringify(pt) });

      (storeLoadById as any)
        .mockResolvedValueOnce(instance)
        .mockResolvedValueOnce(instance)
        .mockResolvedValueOnce(fullEntity);

      let entitySeenByAction: any;
      (ActionRegistry as any).updateAuthorizedMembers = vi.fn().mockImplementation((ctx: any) => {
        entitySeenByAction = ctx.entity;
      });
      (updateAttribute as any).mockResolvedValue({});

      await reportWorkflowAsyncActionResult(mockContext, mockUser, 'instance-id', 'slot-1', 'success');

      // The action must see the full entity with RELATION_CREATED_BY so AUTHOR can resolve
      expect(entitySeenByAction).toEqual(fullEntity);
      expect(entitySeenByAction[RELATION_CREATED_BY]).toBe('org-author-id');
    });
  });

  // ---------------------------------------------------------------------------
  // Status projection wiring — keeps x_opencti_workflow_id in sync on completion
  // ---------------------------------------------------------------------------

  describe('status projection on completion', () => {
    it('projects the completed state onto the full entity after the instance is updated', async () => {
      const fullEntity = { id: 'entity-id', internal_id: 'entity-id', entity_type: 'Incident' };
      const pt = makePendingTransition({ syncActions: [] });
      const instance = makeInstance({ pendingTransition: JSON.stringify(pt), scope: 'GLOBAL' });

      (storeLoadById as any)
        .mockResolvedValueOnce(instance)
        .mockResolvedValueOnce(instance)
        .mockResolvedValueOnce(fullEntity);
      (updateAttribute as any).mockResolvedValue({});

      await reportWorkflowAsyncActionResult(mockContext, mockUser, 'instance-id', 'slot-1', 'success');

      expect(projectWorkflowState).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ id: mockUser.id }), fullEntity, 'reviewing', 'GLOBAL');
      // Must happen after the instance's own currentState/history update, not before.
      const updateAttributeOrder = (updateAttribute as any).mock.invocationCallOrder.at(-1);
      const projectionOrder = (projectWorkflowState as any).mock.invocationCallOrder[0];
      expect(projectionOrder).toBeGreaterThan(updateAttributeOrder);
    });

    it('skips projection and logs a warning when the full entity could not be loaded', async () => {
      const pt = makePendingTransition({ syncActions: [] });
      const instance = makeInstance({ pendingTransition: JSON.stringify(pt) });

      (storeLoadById as any)
        .mockResolvedValueOnce(instance)
        .mockResolvedValueOnce(instance)
        .mockResolvedValueOnce(null);
      (updateAttribute as any).mockResolvedValue({});

      await reportWorkflowAsyncActionResult(mockContext, mockUser, 'instance-id', 'slot-1', 'success');

      expect(projectWorkflowState).not.toHaveBeenCalled();
      expect(logApp.warn).toHaveBeenCalledWith(
        '[workflow-async-completion] Skipping status projection: entity could not be loaded',
        expect.objectContaining({ entityId: 'entity-id' }),
      );
    });
  });

  // ---------------------------------------------------------------------------
  // Additional edge-case coverage
  // ---------------------------------------------------------------------------

  it('sets pendingStatus=error with a stringified message when a syncAction throws a non-Error value', async () => {
    const pt = makePendingTransition({
      asyncActions: [
        { id: 'slot-1', workId: 'work-1', type: 'asyncBulkAction', status: 'pending' },
      ],
      syncActions: [{ type: 'throwingStringAction', params: {} }],
    });
    (storeLoadById as any).mockResolvedValue(
      makeInstance({ pendingTransition: JSON.stringify(pt) }),
    );
    (ActionRegistry as any).throwingStringAction = vi.fn().mockRejectedValue('plain string failure');
    (updateAttribute as any).mockResolvedValue({});

    await reportWorkflowAsyncActionResult(mockContext, mockUser, 'instance-id', 'slot-1', 'success');

    const calls = (updateAttribute as any).mock.calls;
    const lastPatches = calls[calls.length - 1][4];
    expect(lastPatches.find((p: any) => p.key === 'pendingError')?.value[0]).toContain('plain string failure');
  });

  it('sets pendingStatus=error with a stringified message when an onEnter action throws a non-Error value', async () => {
    const pt = makePendingTransition({
      asyncActions: [
        { id: 'slot-1', workId: 'work-1', type: 'asyncBulkAction', status: 'pending' },
      ],
      syncActions: [],
      onEnterActions: [{ type: 'throwingStringOnEnter', params: {} }],
    });
    (storeLoadById as any).mockResolvedValue(
      makeInstance({ pendingTransition: JSON.stringify(pt) }),
    );
    (ActionRegistry as any).throwingStringOnEnter = vi.fn().mockRejectedValue('plain string onEnter failure');
    (updateAttribute as any).mockResolvedValue({});

    await reportWorkflowAsyncActionResult(mockContext, mockUser, 'instance-id', 'slot-1', 'success');

    const calls = (updateAttribute as any).mock.calls;
    const lastPatches = calls[calls.length - 1][4];
    expect(lastPatches.find((p: any) => p.key === 'pendingError')?.value[0]).toContain('plain string onEnter failure');
  });

  it('starts a fresh history when the instance history is malformed JSON', async () => {
    const pt = makePendingTransition({
      asyncActions: [
        { id: 'slot-1', workId: 'work-1', type: 'asyncBulkAction', status: 'pending' },
      ],
      syncActions: [],
    });
    (storeLoadById as any).mockResolvedValue(
      makeInstance({ pendingTransition: JSON.stringify(pt), history: '{ not valid json' }),
    );
    (updateAttribute as any).mockResolvedValue({});

    await reportWorkflowAsyncActionResult(mockContext, mockUser, 'instance-id', 'slot-1', 'success');

    const [, , , , patches] = (updateAttribute as any).mock.calls[0];
    const history = JSON.parse(patches.find((p: any) => p.key === 'history')?.value[0] ?? '[]');
    expect(history).toHaveLength(1);
    expect(history[0].event).toBe('submit');
  });

  it('starts a fresh history when the instance history is empty/falsy', async () => {
    const pt = makePendingTransition({
      asyncActions: [
        { id: 'slot-1', workId: 'work-1', type: 'asyncBulkAction', status: 'pending' },
      ],
      syncActions: [],
    });
    (storeLoadById as any).mockResolvedValue(
      makeInstance({ pendingTransition: JSON.stringify(pt), history: '' }),
    );
    (updateAttribute as any).mockResolvedValue({});

    await reportWorkflowAsyncActionResult(mockContext, mockUser, 'instance-id', 'slot-1', 'success');

    const [, , , , patches] = (updateAttribute as any).mock.calls[0];
    const history = JSON.parse(patches.find((p: any) => p.key === 'history')?.value[0] ?? '[]');
    expect(history).toHaveLength(1);
    expect(history[0].event).toBe('submit');
  });

  it('includes the comment in the new history entry when the transition has one', async () => {
    const pt = makePendingTransition({
      asyncActions: [
        { id: 'slot-1', workId: 'work-1', type: 'asyncBulkAction', status: 'pending' },
      ],
      syncActions: [],
      comment: 'looks good to me',
    });
    (storeLoadById as any).mockResolvedValue(
      makeInstance({ pendingTransition: JSON.stringify(pt) }),
    );
    (updateAttribute as any).mockResolvedValue({});

    await reportWorkflowAsyncActionResult(mockContext, mockUser, 'instance-id', 'slot-1', 'success');

    const [, , , , patches] = (updateAttribute as any).mock.calls[0];
    const history = JSON.parse(patches.find((p: any) => p.key === 'history')?.value[0] ?? '[]');
    expect(history[history.length - 1].comment).toBe('looks good to me');
  });

  it('passes runtimeParams through to actions, defaulting to {} when absent', async () => {
    const pt = makePendingTransition({
      asyncActions: [
        { id: 'slot-1', workId: 'work-1', type: 'asyncBulkAction', status: 'pending' },
      ],
      syncActions: [{ type: 'captureRuntimeParams', params: {} }],
      runtimeParams: undefined,
    });
    (storeLoadById as any).mockResolvedValue(
      makeInstance({ pendingTransition: JSON.stringify(pt) }),
    );
    let capturedRuntimeParams: any;
    (ActionRegistry as any).captureRuntimeParams = vi.fn().mockImplementation((ctx: any) => {
      capturedRuntimeParams = ctx.runtimeParams;
    });
    (updateAttribute as any).mockResolvedValue({});

    await reportWorkflowAsyncActionResult(mockContext, mockUser, 'instance-id', 'slot-1', 'success');

    expect(capturedRuntimeParams).toEqual({});
  });
});

describe('appendWorkflowHistoryEntry', () => {
  it('appends the entry at the end of the history', () => {
    expect(appendWorkflowHistoryEntry([{ state: 'draft' }], { state: 'reviewing' })).toEqual([{ state: 'draft' }, { state: 'reviewing' }]);
  });

  it('keeps only the latest 200 entries', () => {
    const fullHistory = Array.from({ length: 200 }, (_, i) => ({ state: `state-${i}` }));

    const history = appendWorkflowHistoryEntry(fullHistory, { state: 'reviewing' });

    expect(history).toHaveLength(200);
    expect(history[0]).toEqual({ state: 'state-1' });
    expect(history[199]).toEqual({ state: 'reviewing' });
  });
});
