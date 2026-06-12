import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ActionRegistry } from '../../../src/modules/workflow/registry/workflow-actions';

vi.mock('../../../src/modules/draftWorkspace/draftWorkspace-domain', () => ({
  validateDraftWorkspace: vi.fn(),
  draftWorkspaceEditAuthorizedMembers: vi.fn(),
}));

vi.mock('../../../src/schema/identifier', () => ({
  generateInternalId: vi.fn().mockReturnValue('generated-slot-id'),
}));

vi.mock('../../../src/config/conf', () => ({
  logApp: { info: vi.fn(), error: vi.fn(), warn: vi.fn() },
}));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const makeTask = (workId = 'work-id') => ({ work_id: workId });

const makeContext = (overrides: Record<string, unknown> = {}) => ({
  user: { id: 'user-id' },
  entity: { id: 'entity-id', internal_id: 'entity-id', entity_type: 'Incident' },
  context: { user: { id: 'user-id' } },
  runtimeParams: {},
  pendingAsyncSlots: [] as any[],
  __createListTask: vi.fn().mockResolvedValue(makeTask()),
  __workflowInstanceId: 'instance-id',
  __draftEntityIds: [],
  ...overrides,
});

const defaultParams = {
  scope: 'KNOWLEDGE',
  actions: [{ type: 'SHARE', context: { values: ['org-1'] } }],
  failOnAnyError: true,
};

describe('ActionRegistry.asyncBulkAction', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('logs an error and returns without throwing when __createListTask is not injected', async () => {
    const { logApp } = await import('../../../src/config/conf');
    const ctx = makeContext({ __createListTask: undefined });
    await expect(ActionRegistry.asyncBulkAction(ctx, defaultParams)).resolves.toBeUndefined();
    expect(logApp.error).toHaveBeenCalledWith(expect.stringContaining('__createListTask not injected'));
  });

  it('uses the entity id in ids[] for a non-draft entity', async () => {
    const ctx = makeContext();
    await ActionRegistry.asyncBulkAction(ctx, defaultParams);
    expect(ctx.__createListTask).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      expect.objectContaining({ ids: ['entity-id'] }),
    );
  });

  it('uses __draftEntityIds when entity is a DraftWorkspace', async () => {
    const ctx = makeContext({
      entity: { id: 'draft-id', internal_id: 'draft-id', entity_type: 'DraftWorkspace' },
      __draftEntityIds: ['stix-1', 'stix-2', 'stix-3'],
    });
    await ActionRegistry.asyncBulkAction(ctx, defaultParams);
    expect(ctx.__createListTask).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      expect.objectContaining({ ids: ['stix-1', 'stix-2', 'stix-3'] }),
    );
  });

  it('falls back to DraftWorkspace entity_id when __draftEntityIds is empty', async () => {
    const ctx = makeContext({
      entity: { id: 'draft-id', internal_id: 'draft-id', entity_type: 'DraftWorkspace', entity_id: 'linked-entity-id' },
      __draftEntityIds: [],
    });
    await ActionRegistry.asyncBulkAction(ctx, defaultParams);
    expect(ctx.__createListTask).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      expect.objectContaining({ ids: ['linked-entity-id'] }),
    );
  });

  it('injects shareOrganizationIds from runtimeParams into SHARE actions with empty context.values', async () => {
    const ctx = makeContext({
      runtimeParams: { shareOrganizationIds: ['org-a', 'org-b'] },
    });
    const params = {
      scope: 'KNOWLEDGE',
      actions: [{ type: 'SHARE', context: { values: [] } }],
    };
    await ActionRegistry.asyncBulkAction(ctx, params);
    const callArgs = ctx.__createListTask.mock.calls[0][2];
    expect(callArgs.actions[0].context.values).toEqual(['org-a', 'org-b']);
  });

  it('injects unshareOrganizationIds from runtimeParams into UNSHARE actions with empty context.values', async () => {
    const ctx = makeContext({
      runtimeParams: { unshareOrganizationIds: ['org-x'] },
    });
    const params = {
      scope: 'KNOWLEDGE',
      actions: [{ type: 'UNSHARE', context: { values: [] } }],
    };
    await ActionRegistry.asyncBulkAction(ctx, params);
    const callArgs = ctx.__createListTask.mock.calls[0][2];
    expect(callArgs.actions[0].context.values).toEqual(['org-x']);
  });

  it('does NOT overwrite pre-filled context.values on SHARE actions', async () => {
    const ctx = makeContext({
      runtimeParams: { shareOrganizationIds: ['should-not-use'] },
    });
    const params = {
      scope: 'KNOWLEDGE',
      actions: [{ type: 'SHARE', context: { values: ['pre-filled-org'] } }],
    };
    await ActionRegistry.asyncBulkAction(ctx, params);
    const callArgs = ctx.__createListTask.mock.calls[0][2];
    expect(callArgs.actions[0].context.values).toEqual(['pre-filled-org']);
  });

  it('pushes a slot onto pendingAsyncSlots with correct fields', async () => {
    const ctx = makeContext();
    await ActionRegistry.asyncBulkAction(ctx, defaultParams);
    expect(ctx.pendingAsyncSlots).toHaveLength(1);
    const slot = ctx.pendingAsyncSlots[0];
    expect(slot.id).toBe('generated-slot-id');
    expect(slot.workId).toBe('work-id');
    expect(slot.type).toBe('asyncBulkAction');
    expect(slot.status).toBe('pending');
    expect(slot._failOnAnyError).toBe(true);
  });

  it('does not crash when pendingAsyncSlots is not an array', async () => {
    const ctx = makeContext({ pendingAsyncSlots: undefined });
    await expect(ActionRegistry.asyncBulkAction(ctx, defaultParams)).resolves.toBeUndefined();
  });

  it('passes draft_context on the task context when entity is a DraftWorkspace', async () => {
    const ctx = makeContext({
      entity: { id: 'draft-id', internal_id: 'draft-id', entity_type: 'DraftWorkspace' },
      __draftEntityIds: ['stix-1'],
    });
    await ActionRegistry.asyncBulkAction(ctx, defaultParams);
    const [taskContext] = ctx.__createListTask.mock.calls[0];
    expect(taskContext.draft_context).toBe('draft-id');
  });

  it('stores workflow_instance_id and workflow_action_id on the task', async () => {
    const ctx = makeContext();
    await ActionRegistry.asyncBulkAction(ctx, defaultParams);
    const callArgs = ctx.__createListTask.mock.calls[0][2];
    expect(callArgs.workflow_instance_id).toBe('instance-id');
    expect(callArgs.workflow_action_id).toBe('generated-slot-id');
  });
});
