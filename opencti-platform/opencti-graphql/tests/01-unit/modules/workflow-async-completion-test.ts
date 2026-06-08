import { beforeEach, describe, expect, it, vi } from 'vitest';
import { reportWorkflowAsyncActionResult } from '../../../src/modules/workflow/domain/workflow-async-completion';
import { updateAttribute } from '../../../src/database/middleware';
import { storeLoadById } from '../../../src/database/middleware-loader';
import { ActionRegistry } from '../../../src/modules/workflow/registry/workflow-actions';

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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
const mockContext = { user: { id: 'ctx-user-id' } } as any;
const mockUser = { id: 'user-id' } as any;

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
    (ActionRegistry as any).actionA = vi.fn().mockImplementation(() => { calls.push('A'); });
    (ActionRegistry as any).actionB = vi.fn().mockImplementation(() => { calls.push('B'); });
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
});
