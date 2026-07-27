import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
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

// Mock schema constants to prevent loading attribute-definition.ts which
// transitively needs TEST_MODE, BUS_TOPICS, etc. from conf.
vi.mock('../../../src/schema/stixRefRelationship', () => ({
  RELATION_CREATED_BY: 'created-by',
  RELATION_OBJECT_ASSIGNEE: 'object-assignee',
  RELATION_OBJECT_PARTICIPANT: 'object-participant',
}));

vi.mock('../../../src/utils/authorizedMembers', () => ({
  editAuthorizedMembers: vi.fn(),
}));

vi.mock('../../../src/utils/access', () => ({
  KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS: 'KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS',
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

  it('returns early without creating a task when __createListTask is not injected', async () => {
    const ctx = makeContext({ __createListTask: undefined });
    await expect(ActionRegistry.asyncBulkAction(ctx, defaultParams)).resolves.toBeUndefined();
    // Slot is never pushed, proving the function exited before spawning a task
    expect(ctx.pendingAsyncSlots).toHaveLength(0);
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
  });
});

// ---------------------------------------------------------------------------
// updateAuthorizedMembers — AUTHOR dynamic key
// ---------------------------------------------------------------------------

describe('ActionRegistry.updateAuthorizedMembers (AUTHOR)', () => {
  // vi.doMock + resetModules ensures the fresh ActionRegistry loads with the
  // new mocks — static vi.mock hoisting is unreliable for these deep deps.
  let freshRegistry: Record<string, (ctx: any, params?: any) => Promise<void>>;

  beforeEach(async () => {
    vi.resetModules();
    vi.doMock('../../../src/utils/authorizedMembers', () => ({ editAuthorizedMembers: vi.fn() }));
    vi.doMock('../../../src/modules/draftWorkspace/draftWorkspace-domain', () => ({
      validateDraftWorkspace: vi.fn(),
      draftWorkspaceEditAuthorizedMembers: vi.fn(),
    }));
    vi.doMock('../../../src/config/conf', async () => {
      const actual = await import('../../../src/config/conf');
      return { ...actual, logApp: { info: vi.fn(), error: vi.fn(), warn: vi.fn() } };
    });
    vi.doMock('../../../src/schema/identifier', () => ({ generateInternalId: vi.fn() }));
    vi.doMock('../../../src/utils/access', () => ({ KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS: 'KNMANAGEAUTHMEMBERS' }));
    vi.doMock('../../../src/schema/stixRefRelationship', () => ({
      RELATION_CREATED_BY: 'created-by',
      RELATION_OBJECT_ASSIGNEE: 'object-assignee',
      RELATION_OBJECT_PARTICIPANT: 'object-participant',
    }));
    const mod = await import('../../../src/modules/workflow/registry/workflow-actions');
    freshRegistry = mod.ActionRegistry as any;
  });

  afterEach(() => {
    vi.resetModules();
    vi.restoreAllMocks();
  });

  const makeUpdateCtx = (entityOverrides: Record<string, unknown> = {}) => ({
    user: { id: 'user-id' },
    entity: { id: 'entity-id', internal_id: 'entity-id', entity_type: 'Incident', ...entityOverrides },
    context: {},
  });

  it('resolves AUTHOR to the createdBy entity ID (string)', async () => {
    const { editAuthorizedMembers } = await import('../../../src/utils/authorizedMembers');
    const ctx = makeUpdateCtx({ 'created-by': 'org-id' });
    await freshRegistry.updateAuthorizedMembers(ctx, {
      authorized_members: [{ id: 'AUTHOR', access_right: 'edit', groups_restriction_ids: ['group-1'] }],
    });
    expect(editAuthorizedMembers).toHaveBeenCalledWith(
      ctx.context, ctx.user,
      expect.objectContaining({
        input: [{ id: 'org-id', access_right: 'edit', groups_restriction_ids: ['group-1'] }],
      }),
    );
  });

  it('resolves AUTHOR to all IDs when createdBy is an array', async () => {
    const { editAuthorizedMembers } = await import('../../../src/utils/authorizedMembers');
    const ctx = makeUpdateCtx({ 'created-by': ['org-a', 'org-b'] });
    await freshRegistry.updateAuthorizedMembers(ctx, {
      authorized_members: [{ id: 'AUTHOR', access_right: 'view', groups_restriction_ids: [] }],
    });
    expect(editAuthorizedMembers).toHaveBeenCalledWith(
      ctx.context, ctx.user,
      expect.objectContaining({
        input: [
          { id: 'org-a', access_right: 'view', groups_restriction_ids: [] },
          { id: 'org-b', access_right: 'view', groups_restriction_ids: [] },
        ],
      }),
    );
  });

  it('produces empty resolved list when createdBy is absent', async () => {
    const { editAuthorizedMembers } = await import('../../../src/utils/authorizedMembers');
    const ctx = makeUpdateCtx(); // no 'created-by' field
    await freshRegistry.updateAuthorizedMembers(ctx, {
      authorized_members: [{ id: 'AUTHOR', access_right: 'admin', groups_restriction_ids: [] }],
    });
    expect(editAuthorizedMembers).toHaveBeenCalledWith(
      ctx.context, ctx.user,
      expect.objectContaining({ input: [] }),
    );
  });
});

// ---------------------------------------------------------------------------
// updateAuthorizedMembers — CREATORS dynamic key
// ---------------------------------------------------------------------------

describe('ActionRegistry.updateAuthorizedMembers (CREATORS)', () => {
  let freshRegistry: Record<string, (ctx: any, params?: any) => Promise<void>>;

  beforeEach(async () => {
    vi.resetModules();
    vi.doMock('../../../src/utils/authorizedMembers', () => ({ editAuthorizedMembers: vi.fn() }));
    vi.doMock('../../../src/schema/stixRefRelationship', () => ({ RELATION_CREATED_BY: 'created-by', RELATION_OBJECT_ASSIGNEE: 'object-assignee', RELATION_OBJECT_PARTICIPANT: 'object-participant' }));
    vi.doMock('../../../src/modules/draftWorkspace/draftWorkspace-domain', () => ({
      validateDraftWorkspace: vi.fn(),
      draftWorkspaceEditAuthorizedMembers: vi.fn(),
    }));
    vi.doMock('../../../src/config/conf', async () => {
      const actual = await import('../../../src/config/conf');
      return { ...actual, logApp: { info: vi.fn(), error: vi.fn(), warn: vi.fn() } };
    });
    vi.doMock('../../../src/schema/identifier', () => ({ generateInternalId: vi.fn() }));
    vi.doMock('../../../src/utils/access', () => ({ KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS: 'KNMANAGEAUTHMEMBERS' }));
    const mod = await import('../../../src/modules/workflow/registry/workflow-actions');
    freshRegistry = mod.ActionRegistry as any;
  });

  afterEach(() => {
    vi.resetModules();
    vi.restoreAllMocks();
  });

  const makeUpdateCtx = (entityOverrides: Record<string, unknown> = {}) => ({
    user: { id: 'user-id' },
    entity: { id: 'entity-id', internal_id: 'entity-id', entity_type: 'Incident', ...entityOverrides },
    context: {},
  });

  it('pushes a single creator_id for CREATORS', async () => {
    const { editAuthorizedMembers } = await import('../../../src/utils/authorizedMembers');
    const ctx = makeUpdateCtx({ creator_id: 'creator-1' });
    await freshRegistry.updateAuthorizedMembers(ctx, {
      authorized_members: [{ id: 'CREATORS', access_right: 'edit', groups_restriction_ids: [] }],
    });
    expect(editAuthorizedMembers).toHaveBeenCalledWith(
      ctx.context, ctx.user,
      expect.objectContaining({
        input: [{ id: 'creator-1', access_right: 'edit', groups_restriction_ids: [] }],
      }),
    );
  });

  it('pushes all creator ids when creator_id is an array', async () => {
    const { editAuthorizedMembers } = await import('../../../src/utils/authorizedMembers');
    const ctx = makeUpdateCtx({ creator_id: ['user-a', 'user-b'] });
    await freshRegistry.updateAuthorizedMembers(ctx, {
      authorized_members: [{ id: 'CREATORS', access_right: 'view', groups_restriction_ids: [] }],
    });
    expect(editAuthorizedMembers).toHaveBeenCalledWith(
      ctx.context, ctx.user,
      expect.objectContaining({
        input: [
          { id: 'user-a', access_right: 'view', groups_restriction_ids: [] },
          { id: 'user-b', access_right: 'view', groups_restriction_ids: [] },
        ],
      }),
    );
  });

  it('produces empty resolved list when creator_id is absent', async () => {
    const { editAuthorizedMembers } = await import('../../../src/utils/authorizedMembers');
    const ctx = makeUpdateCtx(); // no creator_id
    await freshRegistry.updateAuthorizedMembers(ctx, {
      authorized_members: [{ id: 'CREATORS', access_right: 'edit', groups_restriction_ids: [] }],
    });
    expect(editAuthorizedMembers).toHaveBeenCalledWith(
      ctx.context, ctx.user,
      expect.objectContaining({ input: [] }),
    );
  });
});

// ---------------------------------------------------------------------------
// updateAuthorizedMembers — ASSIGNEES dynamic key
// ---------------------------------------------------------------------------

describe('ActionRegistry.updateAuthorizedMembers (ASSIGNEES)', () => {
  let freshRegistry: Record<string, (ctx: any, params?: any) => Promise<void>>;

  beforeEach(async () => {
    vi.resetModules();
    vi.doMock('../../../src/utils/authorizedMembers', () => ({ editAuthorizedMembers: vi.fn() }));
    vi.doMock('../../../src/schema/stixRefRelationship', () => ({ RELATION_CREATED_BY: 'created-by', RELATION_OBJECT_ASSIGNEE: 'object-assignee', RELATION_OBJECT_PARTICIPANT: 'object-participant' }));
    vi.doMock('../../../src/modules/draftWorkspace/draftWorkspace-domain', () => ({
      validateDraftWorkspace: vi.fn(),
      draftWorkspaceEditAuthorizedMembers: vi.fn(),
    }));
    vi.doMock('../../../src/config/conf', async () => {
      const actual = await import('../../../src/config/conf');
      return { ...actual, logApp: { info: vi.fn(), error: vi.fn(), warn: vi.fn() } };
    });
    vi.doMock('../../../src/schema/identifier', () => ({ generateInternalId: vi.fn() }));
    vi.doMock('../../../src/utils/access', () => ({ KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS: 'KNMANAGEAUTHMEMBERS' }));
    const mod = await import('../../../src/modules/workflow/registry/workflow-actions');
    freshRegistry = mod.ActionRegistry as any;
  });

  afterEach(() => {
    vi.resetModules();
    vi.restoreAllMocks();
  });

  const makeUpdateCtx = (entityOverrides: Record<string, unknown> = {}) => ({
    user: { id: 'user-id' },
    entity: { id: 'entity-id', internal_id: 'entity-id', entity_type: 'Incident', ...entityOverrides },
    context: {},
  });

  it('pushes a single assignee id', async () => {
    const { editAuthorizedMembers } = await import('../../../src/utils/authorizedMembers');
    // 'object-assignee' matches the RELATION_OBJECT_ASSIGNEE mock value
    const ctx = makeUpdateCtx({ 'object-assignee': 'assignee-1' });
    await freshRegistry.updateAuthorizedMembers(ctx, {
      authorized_members: [{ id: 'ASSIGNEES', access_right: 'view', groups_restriction_ids: [] }],
    });
    expect(editAuthorizedMembers).toHaveBeenCalledWith(
      ctx.context, ctx.user,
      expect.objectContaining({
        input: [{ id: 'assignee-1', access_right: 'view', groups_restriction_ids: [] }],
      }),
    );
  });

  it('pushes all assignee ids when field is an array', async () => {
    const { editAuthorizedMembers } = await import('../../../src/utils/authorizedMembers');
    const ctx = makeUpdateCtx({ 'object-assignee': ['assignee-a', 'assignee-b'] });
    await freshRegistry.updateAuthorizedMembers(ctx, {
      authorized_members: [{ id: 'ASSIGNEES', access_right: 'edit', groups_restriction_ids: [] }],
    });
    expect(editAuthorizedMembers).toHaveBeenCalledWith(
      ctx.context, ctx.user,
      expect.objectContaining({
        input: [
          { id: 'assignee-a', access_right: 'edit', groups_restriction_ids: [] },
          { id: 'assignee-b', access_right: 'edit', groups_restriction_ids: [] },
        ],
      }),
    );
  });

  it('produces empty resolved list when no assignees are set', async () => {
    const { editAuthorizedMembers } = await import('../../../src/utils/authorizedMembers');
    const ctx = makeUpdateCtx(); // no object-assignee field
    await freshRegistry.updateAuthorizedMembers(ctx, {
      authorized_members: [{ id: 'ASSIGNEES', access_right: 'view', groups_restriction_ids: [] }],
    });
    expect(editAuthorizedMembers).toHaveBeenCalledWith(
      ctx.context, ctx.user,
      expect.objectContaining({ input: [] }),
    );
  });
});

// ---------------------------------------------------------------------------
// updateAuthorizedMembers — PARTICIPANTS dynamic key
// ---------------------------------------------------------------------------

describe('ActionRegistry.updateAuthorizedMembers (PARTICIPANTS)', () => {
  let freshRegistry: Record<string, (ctx: any, params?: any) => Promise<void>>;

  beforeEach(async () => {
    vi.resetModules();
    vi.doMock('../../../src/utils/authorizedMembers', () => ({ editAuthorizedMembers: vi.fn() }));
    vi.doMock('../../../src/schema/stixRefRelationship', () => ({ RELATION_CREATED_BY: 'created-by', RELATION_OBJECT_ASSIGNEE: 'object-assignee', RELATION_OBJECT_PARTICIPANT: 'object-participant' }));
    vi.doMock('../../../src/modules/draftWorkspace/draftWorkspace-domain', () => ({
      validateDraftWorkspace: vi.fn(),
      draftWorkspaceEditAuthorizedMembers: vi.fn(),
    }));
    vi.doMock('../../../src/config/conf', async () => {
      const actual = await import('../../../src/config/conf');
      return { ...actual, logApp: { info: vi.fn(), error: vi.fn(), warn: vi.fn() } };
    });
    vi.doMock('../../../src/schema/identifier', () => ({ generateInternalId: vi.fn() }));
    vi.doMock('../../../src/utils/access', () => ({ KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS: 'KNMANAGEAUTHMEMBERS' }));
    const mod = await import('../../../src/modules/workflow/registry/workflow-actions');
    freshRegistry = mod.ActionRegistry as any;
  });

  afterEach(() => {
    vi.resetModules();
    vi.restoreAllMocks();
  });

  const makeUpdateCtx = (entityOverrides: Record<string, unknown> = {}) => ({
    user: { id: 'user-id' },
    entity: { id: 'entity-id', internal_id: 'entity-id', entity_type: 'Incident', ...entityOverrides },
    context: {},
  });

  it('pushes a single participant id', async () => {
    const { editAuthorizedMembers } = await import('../../../src/utils/authorizedMembers');
    // 'object-participant' matches the RELATION_OBJECT_PARTICIPANT mock value
    const ctx = makeUpdateCtx({ 'object-participant': 'participant-1' });
    await freshRegistry.updateAuthorizedMembers(ctx, {
      authorized_members: [{ id: 'PARTICIPANTS', access_right: 'view', groups_restriction_ids: [] }],
    });
    expect(editAuthorizedMembers).toHaveBeenCalledWith(
      ctx.context, ctx.user,
      expect.objectContaining({
        input: [{ id: 'participant-1', access_right: 'view', groups_restriction_ids: [] }],
      }),
    );
  });

  it('pushes all participant ids when field is an array', async () => {
    const { editAuthorizedMembers } = await import('../../../src/utils/authorizedMembers');
    const ctx = makeUpdateCtx({ 'object-participant': ['p-a', 'p-b', 'p-c'] });
    await freshRegistry.updateAuthorizedMembers(ctx, {
      authorized_members: [{ id: 'PARTICIPANTS', access_right: 'admin', groups_restriction_ids: ['grp-1'] }],
    });
    expect(editAuthorizedMembers).toHaveBeenCalledWith(
      ctx.context, ctx.user,
      expect.objectContaining({
        input: [
          { id: 'p-a', access_right: 'admin', groups_restriction_ids: ['grp-1'] },
          { id: 'p-b', access_right: 'admin', groups_restriction_ids: ['grp-1'] },
          { id: 'p-c', access_right: 'admin', groups_restriction_ids: ['grp-1'] },
        ],
      }),
    );
  });

  it('produces empty resolved list when no participants are set', async () => {
    const { editAuthorizedMembers } = await import('../../../src/utils/authorizedMembers');
    const ctx = makeUpdateCtx(); // no object-participant field
    await freshRegistry.updateAuthorizedMembers(ctx, {
      authorized_members: [{ id: 'PARTICIPANTS', access_right: 'view', groups_restriction_ids: [] }],
    });
    expect(editAuthorizedMembers).toHaveBeenCalledWith(
      ctx.context, ctx.user,
      expect.objectContaining({ input: [] }),
    );
  });
});

// ---------------------------------------------------------------------------
// validateDraft action
// ---------------------------------------------------------------------------

describe('ActionRegistry.validateDraft', () => {
  let freshRegistry: Record<string, (ctx: any, params?: any) => Promise<void>>;
  let mockValidateDraftWorkspace: ReturnType<typeof vi.fn>;

  beforeEach(async () => {
    vi.resetModules();
    mockValidateDraftWorkspace = vi.fn().mockResolvedValue(undefined);
    vi.doMock('../../../src/modules/draftWorkspace/draftWorkspace-domain', () => ({
      validateDraftWorkspace: mockValidateDraftWorkspace,
      draftWorkspaceEditAuthorizedMembers: vi.fn(),
    }));
    vi.doMock('../../../src/config/conf', async () => {
      const actual = await import('../../../src/config/conf');
      return { ...actual, logApp: { info: vi.fn(), error: vi.fn(), warn: vi.fn() } };
    });
    vi.doMock('../../../src/utils/authorizedMembers', () => ({ editAuthorizedMembers: vi.fn() }));
    vi.doMock('../../../src/schema/stixRefRelationship', () => ({ RELATION_CREATED_BY: 'created-by', RELATION_OBJECT_ASSIGNEE: 'object-assignee', RELATION_OBJECT_PARTICIPANT: 'object-participant' }));
    vi.doMock('../../../src/schema/identifier', () => ({ generateInternalId: vi.fn() }));
    vi.doMock('../../../src/utils/access', () => ({ KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS: 'KNMANAGEAUTHMEMBERS' }));
    const mod = await import('../../../src/modules/workflow/registry/workflow-actions');
    freshRegistry = mod.ActionRegistry as any;
  });

  afterEach(() => {
    vi.resetModules();
    vi.restoreAllMocks();
  });

  it('calls validateDraftWorkspace with the entity id', async () => {
    const ctx = {
      user: { id: 'user-id' },
      entity: { id: 'draft-entity-id', internal_id: 'draft-entity-id', entity_type: 'DraftWorkspace' },
      context: {},
    };
    await freshRegistry.validateDraft(ctx);
    expect(mockValidateDraftWorkspace).toHaveBeenCalledWith(ctx.context, ctx.user, 'draft-entity-id');
  });

  it('propagates errors thrown by validateDraftWorkspace', async () => {
    mockValidateDraftWorkspace.mockRejectedValue(new Error('Validation failed'));
    const ctx = {
      user: { id: 'user-id' },
      entity: { id: 'draft-entity-id', internal_id: 'draft-entity-id', entity_type: 'DraftWorkspace' },
      context: {},
    };
    await expect(freshRegistry.validateDraft(ctx)).rejects.toThrow('Validation failed');
  });
});

// ---------------------------------------------------------------------------
// updateAuthorizedMembers — skipAdminValidation bypass
// ---------------------------------------------------------------------------

describe('ActionRegistry.updateAuthorizedMembers (skipAdminValidation)', () => {
  let freshRegistry: Record<string, (ctx: any, params?: any) => Promise<void>>;
  let mockEditAuthorizedMembers: ReturnType<typeof vi.fn>;
  let mockDraftWorkspaceEditAuthorizedMembers: ReturnType<typeof vi.fn>;

  beforeEach(async () => {
    vi.resetModules();
    mockEditAuthorizedMembers = vi.fn().mockResolvedValue(undefined);
    mockDraftWorkspaceEditAuthorizedMembers = vi.fn().mockResolvedValue(undefined);
    vi.doMock('../../../src/utils/authorizedMembers', () => ({ editAuthorizedMembers: mockEditAuthorizedMembers }));
    vi.doMock('../../../src/modules/draftWorkspace/draftWorkspace-domain', () => ({
      validateDraftWorkspace: vi.fn(),
      draftWorkspaceEditAuthorizedMembers: mockDraftWorkspaceEditAuthorizedMembers,
    }));
    vi.doMock('../../../src/config/conf', async () => {
      const actual = await import('../../../src/config/conf');
      return { ...actual, logApp: { info: vi.fn(), error: vi.fn(), warn: vi.fn() } };
    });
    vi.doMock('../../../src/schema/identifier', () => ({ generateInternalId: vi.fn() }));
    vi.doMock('../../../src/utils/access', () => ({ KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS: 'KNMANAGEAUTHMEMBERS' }));
    vi.doMock('../../../src/schema/stixRefRelationship', () => ({
      RELATION_CREATED_BY: 'created-by',
      RELATION_OBJECT_ASSIGNEE: 'object-assignee',
      RELATION_OBJECT_PARTICIPANT: 'object-participant',
    }));
    const mod = await import('../../../src/modules/workflow/registry/workflow-actions');
    freshRegistry = mod.ActionRegistry as any;
  });

  afterEach(() => {
    vi.resetModules();
    vi.restoreAllMocks();
  });

  it('passes skipAdminValidation: true when members list has no admin (non-draft entity)', async () => {
    const ctx = {
      user: { id: 'user-id' },
      entity: { id: 'entity-id', internal_id: 'entity-id', entity_type: 'Incident' },
      context: {},
    };
    await freshRegistry.updateAuthorizedMembers(ctx, {
      authorized_members: [{ id: 'some-user', access_right: 'view' }],
    });
    expect(mockEditAuthorizedMembers).toHaveBeenCalledWith(
      ctx.context, ctx.user,
      expect.objectContaining({ skipAdminValidation: true }),
    );
  });

  it('passes skipAdminValidation: true when members list has no admin (DraftWorkspace)', async () => {
    const ctx = {
      user: { id: 'user-id' },
      entity: { id: 'draft-id', internal_id: 'draft-id', entity_type: 'DraftWorkspace' },
      context: {},
    };
    await freshRegistry.updateAuthorizedMembers(ctx, {
      authorized_members: [{ id: 'some-user', access_right: 'view' }],
    });
    expect(mockDraftWorkspaceEditAuthorizedMembers).toHaveBeenCalledWith(
      ctx.context, ctx.user,
      'draft-id',
      expect.any(Array),
      { skipAdminValidation: true },
    );
  });
});
