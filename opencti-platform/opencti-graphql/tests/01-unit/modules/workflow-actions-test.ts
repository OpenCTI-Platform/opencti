import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ActionRegistry } from '../../../src/modules/workflow/registry/workflow-actions';

vi.mock('../../../src/modules/draftWorkspace/draftWorkspace-domain', () => ({
  validateDraftWorkspace: vi.fn(),
  draftWorkspaceEditAuthorizedMembers: vi.fn(),
}));

vi.mock('../../../src/schema/identifier', () => ({
  generateInternalId: vi.fn().mockReturnValue('generated-slot-id'),
}));

vi.mock('../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/config/conf')>();
  return {
    ...actual,
    logApp: { info: vi.fn(), error: vi.fn(), warn: vi.fn() },
  };
});

vi.mock('../../../src/utils/authorizedMembers', () => ({
  editAuthorizedMembers: vi.fn(),
}));

// storeLoadById is used to resolve the AUTHOR entity type.
// Each test that needs AUTHOR resolution will configure the return value.
vi.mock('../../../src/database/middleware-loader', () => ({
  storeLoadById: vi.fn(),
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

// ---------------------------------------------------------------------------
// updateAuthorizedMembers — dynamic key resolution
// ---------------------------------------------------------------------------

describe('ActionRegistry.updateAuthorizedMembers', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const makeUpdateCtx = (entityOverrides: Record<string, unknown> = {}) => ({
    user: { id: 'user-id' },
    entity: {
      id: 'entity-id',
      internal_id: 'entity-id',
      entity_type: 'DraftWorkspace',
      ...entityOverrides,
    },
    context: {},
  });

  it('passes static member IDs through unchanged', async () => {
    const { draftWorkspaceEditAuthorizedMembers } = await import('../../../src/modules/draftWorkspace/draftWorkspace-domain');
    const ctx = makeUpdateCtx();
    const params = {
      authorized_members: [{ id: 'static-user-id', access_right: 'view', groups_restriction_ids: [] }],
    };
    await ActionRegistry.updateAuthorizedMembers(ctx, params);
    expect(draftWorkspaceEditAuthorizedMembers).toHaveBeenCalledWith(
      ctx.context,
      ctx.user,
      'entity-id',
      [{ id: 'static-user-id', access_right: 'view', groups_restriction_ids: [] }],
    );
  });

  it('resolves AUTHOR to the created-by org ID when author is an Organization', async () => {
    const { storeLoadById } = await import('../../../src/database/middleware-loader');
    const { draftWorkspaceEditAuthorizedMembers } = await import('../../../src/modules/draftWorkspace/draftWorkspace-domain');
    vi.mocked(storeLoadById).mockResolvedValue({ entity_type: 'Organization' } as any);

    const ctx = makeUpdateCtx({ 'created-by': 'org-id' });
    await ActionRegistry.updateAuthorizedMembers(ctx, {
      authorized_members: [{ id: 'AUTHOR', access_right: 'edit', groups_restriction_ids: ['group-1'] }],
    });
    expect(draftWorkspaceEditAuthorizedMembers).toHaveBeenCalledWith(
      ctx.context,
      ctx.user,
      'entity-id',
      [{ id: 'org-id', access_right: 'edit', groups_restriction_ids: ['group-1'] }],
    );
  });

  it('skips AUTHOR when created-by entity is not an Organization', async () => {
    const { storeLoadById } = await import('../../../src/database/middleware-loader');
    const { draftWorkspaceEditAuthorizedMembers } = await import('../../../src/modules/draftWorkspace/draftWorkspace-domain');
    vi.mocked(storeLoadById).mockResolvedValue({ entity_type: 'Individual' } as any);

    const ctx = makeUpdateCtx({ 'created-by': 'individual-id' });
    await ActionRegistry.updateAuthorizedMembers(ctx, {
      authorized_members: [{ id: 'AUTHOR', access_right: 'edit', groups_restriction_ids: [] }],
    });
    expect(draftWorkspaceEditAuthorizedMembers).toHaveBeenCalledWith(
      ctx.context,
      ctx.user,
      'entity-id',
      [],
    );
  });

  it('skips AUTHOR when created-by field is absent', async () => {
    const { draftWorkspaceEditAuthorizedMembers } = await import('../../../src/modules/draftWorkspace/draftWorkspace-domain');
    const ctx = makeUpdateCtx(); // no 'created-by' field
    await ActionRegistry.updateAuthorizedMembers(ctx, {
      authorized_members: [{ id: 'AUTHOR', access_right: 'admin', groups_restriction_ids: [] }],
    });
    expect(draftWorkspaceEditAuthorizedMembers).toHaveBeenCalledWith(ctx.context, ctx.user, 'entity-id', []);
  });

  it('resolves CREATORS from creator_id array', async () => {
    const { draftWorkspaceEditAuthorizedMembers } = await import('../../../src/modules/draftWorkspace/draftWorkspace-domain');
    const ctx = makeUpdateCtx({ creator_id: ['user-a', 'user-b'] });
    await ActionRegistry.updateAuthorizedMembers(ctx, {
      authorized_members: [{ id: 'CREATORS', access_right: 'view', groups_restriction_ids: [] }],
    });
    expect(draftWorkspaceEditAuthorizedMembers).toHaveBeenCalledWith(
      ctx.context,
      ctx.user,
      'entity-id',
      [
        { id: 'user-a', access_right: 'view', groups_restriction_ids: [] },
        { id: 'user-b', access_right: 'view', groups_restriction_ids: [] },
      ],
    );
  });

  it('resolves PARTICIPANTS from object-participant array', async () => {
    const { draftWorkspaceEditAuthorizedMembers } = await import('../../../src/modules/draftWorkspace/draftWorkspace-domain');
    const ctx = makeUpdateCtx({ 'object-participant': ['p-1', 'p-2'] });
    await ActionRegistry.updateAuthorizedMembers(ctx, {
      authorized_members: [{ id: 'PARTICIPANTS', access_right: 'view', groups_restriction_ids: [] }],
    });
    expect(draftWorkspaceEditAuthorizedMembers).toHaveBeenCalledWith(
      ctx.context,
      ctx.user,
      'entity-id',
      [
        { id: 'p-1', access_right: 'view', groups_restriction_ids: [] },
        { id: 'p-2', access_right: 'view', groups_restriction_ids: [] },
      ],
    );
  });

  it('resolves ASSIGNEES from object-assignee array', async () => {
    const { draftWorkspaceEditAuthorizedMembers } = await import('../../../src/modules/draftWorkspace/draftWorkspace-domain');
    const ctx = makeUpdateCtx({ 'object-assignee': ['a-1'] });
    await ActionRegistry.updateAuthorizedMembers(ctx, {
      authorized_members: [{ id: 'ASSIGNEES', access_right: 'admin', groups_restriction_ids: [] }],
    });
    expect(draftWorkspaceEditAuthorizedMembers).toHaveBeenCalledWith(
      ctx.context,
      ctx.user,
      'entity-id',
      [{ id: 'a-1', access_right: 'admin', groups_restriction_ids: [] }],
    );
  });

  it('calls editAuthorizedMembers for non-DraftWorkspace entities', async () => {
    const { storeLoadById } = await import('../../../src/database/middleware-loader');
    const { editAuthorizedMembers } = await import('../../../src/utils/authorizedMembers');
    vi.mocked(storeLoadById).mockResolvedValue({ entity_type: 'Organization' } as any);

    const ctx = makeUpdateCtx({ entity_type: 'Report', 'created-by': 'org-id' });
    await ActionRegistry.updateAuthorizedMembers(ctx, {
      authorized_members: [{ id: 'AUTHOR', access_right: 'view', groups_restriction_ids: [] }],
    });
    expect(editAuthorizedMembers).toHaveBeenCalledWith(
      ctx.context,
      ctx.user,
      expect.objectContaining({
        entityId: 'entity-id',
        entityType: 'Report',
        input: [{ id: 'org-id', access_right: 'view', groups_restriction_ids: [] }],
      }),
    );
  });

  it('resolves a mix of static and dynamic members', async () => {
    const { storeLoadById } = await import('../../../src/database/middleware-loader');
    const { draftWorkspaceEditAuthorizedMembers } = await import('../../../src/modules/draftWorkspace/draftWorkspace-domain');
    vi.mocked(storeLoadById).mockResolvedValue({ entity_type: 'Organization' } as any);

    const ctx = makeUpdateCtx({
      'created-by': 'org-id',
      'object-participant': ['p-1'],
    });
    await ActionRegistry.updateAuthorizedMembers(ctx, {
      authorized_members: [
        { id: 'static-user', access_right: 'admin', groups_restriction_ids: [] },
        { id: 'AUTHOR', access_right: 'edit', groups_restriction_ids: ['g-1'] },
        { id: 'PARTICIPANTS', access_right: 'view', groups_restriction_ids: [] },
      ],
    });
    expect(draftWorkspaceEditAuthorizedMembers).toHaveBeenCalledWith(
      ctx.context,
      ctx.user,
      'entity-id',
      [
        { id: 'static-user', access_right: 'admin', groups_restriction_ids: [] },
        { id: 'org-id', access_right: 'edit', groups_restriction_ids: ['g-1'] },
        { id: 'p-1', access_right: 'view', groups_restriction_ids: [] },
      ],
    );
  });

  // ── scalar (non-array) field values ────────────────────────────────────────

  it('resolves CREATORS from a scalar creator_id string', async () => {
    const { draftWorkspaceEditAuthorizedMembers } = await import('../../../src/modules/draftWorkspace/draftWorkspace-domain');
    const ctx = makeUpdateCtx({ creator_id: 'single-user' });
    await ActionRegistry.updateAuthorizedMembers(ctx, {
      authorized_members: [{ id: 'CREATORS', access_right: 'view', groups_restriction_ids: [] }],
    });
    expect(draftWorkspaceEditAuthorizedMembers).toHaveBeenCalledWith(
      ctx.context, ctx.user, 'entity-id',
      [{ id: 'single-user', access_right: 'view', groups_restriction_ids: [] }],
    );
  });

  it('resolves ASSIGNEES from a scalar object-assignee string', async () => {
    const { draftWorkspaceEditAuthorizedMembers } = await import('../../../src/modules/draftWorkspace/draftWorkspace-domain');
    const ctx = makeUpdateCtx({ 'object-assignee': 'a-scalar' });
    await ActionRegistry.updateAuthorizedMembers(ctx, {
      authorized_members: [{ id: 'ASSIGNEES', access_right: 'view', groups_restriction_ids: [] }],
    });
    expect(draftWorkspaceEditAuthorizedMembers).toHaveBeenCalledWith(
      ctx.context, ctx.user, 'entity-id',
      [{ id: 'a-scalar', access_right: 'view', groups_restriction_ids: [] }],
    );
  });

  it('resolves PARTICIPANTS from a scalar object-participant string', async () => {
    const { draftWorkspaceEditAuthorizedMembers } = await import('../../../src/modules/draftWorkspace/draftWorkspace-domain');
    const ctx = makeUpdateCtx({ 'object-participant': 'p-scalar' });
    await ActionRegistry.updateAuthorizedMembers(ctx, {
      authorized_members: [{ id: 'PARTICIPANTS', access_right: 'edit', groups_restriction_ids: [] }],
    });
    expect(draftWorkspaceEditAuthorizedMembers).toHaveBeenCalledWith(
      ctx.context, ctx.user, 'entity-id',
      [{ id: 'p-scalar', access_right: 'edit', groups_restriction_ids: [] }],
    );
  });

  // ── storeLoadById error path ───────────────────────────────────────────────

  it('skips AUTHOR when storeLoadById rejects', async () => {
    const { storeLoadById } = await import('../../../src/database/middleware-loader');
    const { draftWorkspaceEditAuthorizedMembers } = await import('../../../src/modules/draftWorkspace/draftWorkspace-domain');
    vi.mocked(storeLoadById).mockRejectedValue(new Error('DB unavailable'));
    const ctx = makeUpdateCtx({ 'created-by': 'some-id' });
    await ActionRegistry.updateAuthorizedMembers(ctx, {
      authorized_members: [{ id: 'AUTHOR', access_right: 'edit', groups_restriction_ids: [] }],
    });
    expect(draftWorkspaceEditAuthorizedMembers).toHaveBeenCalledWith(ctx.context, ctx.user, 'entity-id', []);
  });
});

// ---------------------------------------------------------------------------
// log action
// ---------------------------------------------------------------------------

describe('ActionRegistry.log', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('logs with the provided message', async () => {
    const { logApp } = await import('../../../src/config/conf');
    const ctx = makeContext();
    await ActionRegistry.log(ctx, { message: 'hello test' });
    expect(logApp.info).toHaveBeenCalledWith(expect.stringContaining('hello test'));
  });

  it('logs a fallback when no message is provided', async () => {
    const { logApp } = await import('../../../src/config/conf');
    const ctx = makeContext();
    await ActionRegistry.log(ctx, {});
    expect(logApp.info).toHaveBeenCalledWith(expect.stringContaining('No message'));
  });
});

// ---------------------------------------------------------------------------
// validateDraft action
// ---------------------------------------------------------------------------

describe('ActionRegistry.validateDraft', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('calls validateDraftWorkspace with entity id, user and context', async () => {
    const { validateDraftWorkspace } = await import('../../../src/modules/draftWorkspace/draftWorkspace-domain');
    const ctx = makeContext({
      entity: { id: 'draft-id', internal_id: 'draft-id', entity_type: 'DraftWorkspace' },
    });
    await ActionRegistry.validateDraft(ctx, undefined);
    expect(validateDraftWorkspace).toHaveBeenCalledWith(ctx.context, ctx.user, 'draft-id');
  });
});

// ---------------------------------------------------------------------------
// asyncBulkAction — additional branch coverage
// ---------------------------------------------------------------------------

describe('ActionRegistry.asyncBulkAction (extra branches)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('falls back to organizationIds for SHARE when shareOrganizationIds is absent', async () => {
    const ctx = makeContext({ runtimeParams: { organizationIds: ['org-fallback'] } });
    const params = { scope: 'KNOWLEDGE', actions: [{ type: 'SHARE', context: { values: [] } }] };
    await ActionRegistry.asyncBulkAction(ctx, params);
    const callArgs = ctx.__createListTask.mock.calls[0][2];
    expect(callArgs.actions[0].context.values).toEqual(['org-fallback']);
  });

  it('falls back to organizationIds for UNSHARE when unshareOrganizationIds is absent', async () => {
    const ctx = makeContext({ runtimeParams: { organizationIds: ['org-fallback'] } });
    const params = { scope: 'KNOWLEDGE', actions: [{ type: 'UNSHARE', context: { values: [] } }] };
    await ActionRegistry.asyncBulkAction(ctx, params);
    const callArgs = ctx.__createListTask.mock.calls[0][2];
    expect(callArgs.actions[0].context.values).toEqual(['org-fallback']);
  });

  it('does not inject org IDs when runtimeParams has none and context.values is empty', async () => {
    const ctx = makeContext({ runtimeParams: {} });
    const params = { scope: 'KNOWLEDGE', actions: [{ type: 'SHARE', context: { values: [] } }] };
    await ActionRegistry.asyncBulkAction(ctx, params);
    const callArgs = ctx.__createListTask.mock.calls[0][2];
    // orgIds is [] so the condition `orgIds.length > 0` is false — original action returned unchanged
    expect(callArgs.actions[0].context.values).toEqual([]);
  });

  it('produces empty ids[] when entity has no id', async () => {
    const ctx = makeContext({ entity: { entity_type: 'Incident' } });
    await ActionRegistry.asyncBulkAction(ctx, defaultParams);
    const callArgs = ctx.__createListTask.mock.calls[0][2];
    expect(callArgs.ids).toEqual([]);
  });

  it('defaults _failOnAnyError to true when failOnAnyError is not in params', async () => {
    const ctx = makeContext();
    const params = { scope: 'KNOWLEDGE', actions: [{ type: 'SHARE', context: { values: ['o'] } }] };
    await ActionRegistry.asyncBulkAction(ctx, params);
    expect(ctx.pendingAsyncSlots[0]._failOnAnyError).toBe(true);
  });

  it('respects explicit failOnAnyError: false', async () => {
    const ctx = makeContext();
    const params = { scope: 'KNOWLEDGE', actions: [{ type: 'SHARE', context: { values: ['o'] } }], failOnAnyError: false };
    await ActionRegistry.asyncBulkAction(ctx, params);
    expect(ctx.pendingAsyncSlots[0]._failOnAnyError).toBe(false);
  });

  it('uses a fallback description when description param is absent', async () => {
    const ctx = makeContext();
    const params = { scope: 'KNOWLEDGE', actions: [{ type: 'SHARE', context: { values: ['o'] } }] };
    await ActionRegistry.asyncBulkAction(ctx, params);
    const callArgs = ctx.__createListTask.mock.calls[0][2];
    expect(callArgs.description).toBe('Workflow async bulk action');
  });

  it('uses the provided description when set', async () => {
    const ctx = makeContext();
    const params = { scope: 'KNOWLEDGE', description: 'my desc', actions: [{ type: 'SHARE', context: { values: ['o'] } }] };
    await ActionRegistry.asyncBulkAction(ctx, params);
    const callArgs = ctx.__createListTask.mock.calls[0][2];
    expect(callArgs.description).toBe('my desc');
  });

  it('does not set draft_context for non-DraftWorkspace entities', async () => {
    const ctx = makeContext();
    await ActionRegistry.asyncBulkAction(ctx, defaultParams);
    const [taskContext] = ctx.__createListTask.mock.calls[0];
    expect(taskContext.draft_context).toBeUndefined();
  });

  // ── uncovered binary-expr fallbacks ────────────────────────────────────────

  it('uses empty runtimeParams when runtimeParams is absent from context (branch 22)', async () => {
    // Covers `(executionContext as any).runtimeParams ?? {}` right-hand side
    const ctx = makeContext();
    delete (ctx as any).runtimeParams;
    await ActionRegistry.asyncBulkAction(ctx, defaultParams);
    expect(ctx.__createListTask).toHaveBeenCalled();
  });

  it('uses empty actions when params.actions is absent (branch 23)', async () => {
    // Covers `params?.actions ?? []` right-hand side — the map over [] produces []
    const ctx = makeContext();
    const params = { scope: 'KNOWLEDGE', actions: undefined as any };
    await ActionRegistry.asyncBulkAction(ctx, params);
    const callArgs = ctx.__createListTask.mock.calls[0][2];
    expect(callArgs.actions).toEqual([]);
  });

  it('does not inject for UNSHARE when both unshareOrganizationIds and organizationIds are absent (branch 30/31)', async () => {
    // Covers the `?? []` final fallback on line 133 and `orgIds.length > 0` false branch for UNSHARE
    const ctx = makeContext({ runtimeParams: {} });
    const params = { scope: 'KNOWLEDGE', actions: [{ type: 'UNSHARE', context: { values: [] } }] };
    await ActionRegistry.asyncBulkAction(ctx, params);
    const callArgs = ctx.__createListTask.mock.calls[0][2];
    expect(callArgs.actions[0].context.values).toEqual([]);
  });

  it('treats null __draftEntityIds same as undefined — falls back to empty array (branch 32)', async () => {
    // Covers `__draftEntityIds ?? []` right-hand side
    const ctx = makeContext({ __draftEntityIds: null });
    await ActionRegistry.asyncBulkAction(ctx, defaultParams);
    expect(ctx.__createListTask).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      expect.objectContaining({ ids: ['entity-id'] }),
    );
  });

  it('uses empty string for workId when task.work_id is undefined (branch 40)', async () => {
    // Covers `task.work_id ?? ''` right-hand side
    const ctx = makeContext();
    ctx.__createListTask = vi.fn().mockResolvedValue({}); // no work_id field
    await ActionRegistry.asyncBulkAction(ctx, defaultParams);
    expect(ctx.pendingAsyncSlots[0].workId).toBe('');
  });
});

// ---------------------------------------------------------------------------
// updateAuthorizedMembers — additional branch coverage
// ---------------------------------------------------------------------------

describe('ActionRegistry.updateAuthorizedMembers (extra branches)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const makeUpdateCtx = (entityOverrides: Record<string, unknown> = {}) => ({
    user: { id: 'user-id' },
    entity: {
      id: 'entity-id',
      internal_id: 'entity-id',
      entity_type: 'DraftWorkspace',
      ...entityOverrides,
    },
    context: {},
  });

  it('resolves CREATORS to [] when entity has no creator_id field (branch 5 false)', async () => {
    // Covers `entity.creator_id ? [entity.creator_id] : []` — false path
    const { draftWorkspaceEditAuthorizedMembers } = await import('../../../src/modules/draftWorkspace/draftWorkspace-domain');
    const ctx = makeUpdateCtx(); // no creator_id
    await ActionRegistry.updateAuthorizedMembers(ctx, {
      authorized_members: [{ id: 'CREATORS', access_right: 'view', groups_restriction_ids: [] }],
    });
    expect(draftWorkspaceEditAuthorizedMembers).toHaveBeenCalledWith(ctx.context, ctx.user, 'entity-id', []);
  });

  it('resolves ASSIGNEES to [] when entity has no object-assignee field (branch 9 false)', async () => {
    // Covers `entity[RELATION_OBJECT_ASSIGNEE] ? [...] : []` — false path
    const { draftWorkspaceEditAuthorizedMembers } = await import('../../../src/modules/draftWorkspace/draftWorkspace-domain');
    const ctx = makeUpdateCtx(); // no object-assignee
    await ActionRegistry.updateAuthorizedMembers(ctx, {
      authorized_members: [{ id: 'ASSIGNEES', access_right: 'view', groups_restriction_ids: [] }],
    });
    expect(draftWorkspaceEditAuthorizedMembers).toHaveBeenCalledWith(ctx.context, ctx.user, 'entity-id', []);
  });

  it('resolves PARTICIPANTS to [] when entity has no object-participant field (branch 13 false)', async () => {
    // Covers `entity[RELATION_OBJECT_PARTICIPANT] ? [...] : []` — false path
    const { draftWorkspaceEditAuthorizedMembers } = await import('../../../src/modules/draftWorkspace/draftWorkspace-domain');
    const ctx = makeUpdateCtx(); // no object-participant
    await ActionRegistry.updateAuthorizedMembers(ctx, {
      authorized_members: [{ id: 'PARTICIPANTS', access_right: 'view', groups_restriction_ids: [] }],
    });
    expect(draftWorkspaceEditAuthorizedMembers).toHaveBeenCalledWith(ctx.context, ctx.user, 'entity-id', []);
  });

  it('uses [] when params has no authorized_members key (branch 16 false)', async () => {
    // Covers `params?.authorized_members ?? []` right-hand side
    const { draftWorkspaceEditAuthorizedMembers } = await import('../../../src/modules/draftWorkspace/draftWorkspace-domain');
    const ctx = makeUpdateCtx();
    await ActionRegistry.updateAuthorizedMembers(ctx, {} as any);
    expect(draftWorkspaceEditAuthorizedMembers).toHaveBeenCalledWith(ctx.context, ctx.user, 'entity-id', []);
  });

  it('falls back to entity.internal_id when entity.id is absent (branch 18)', async () => {
    // Covers `entity.id ?? entity.internal_id` right-hand side for non-DraftWorkspace
    const { editAuthorizedMembers } = await import('../../../src/utils/authorizedMembers');
    const ctx = {
      user: { id: 'user-id' },
      entity: { internal_id: 'only-internal-id', entity_type: 'Report' }, // no id field
      context: {},
    };
    await ActionRegistry.updateAuthorizedMembers(ctx, {
      authorized_members: [{ id: 'static-user', access_right: 'view', groups_restriction_ids: [] }],
    });
    expect(editAuthorizedMembers).toHaveBeenCalledWith(
      ctx.context, ctx.user,
      expect.objectContaining({ entityId: 'only-internal-id' }),
    );
  });

  it('skips falsy values inside CREATORS array (branch 6 false)', async () => {
    // Covers `if (creatorId)` false branch — falsy element in creator_id array
    const { draftWorkspaceEditAuthorizedMembers } = await import('../../../src/modules/draftWorkspace/draftWorkspace-domain');
    const ctx = makeUpdateCtx({ creator_id: ['', 'real-creator'] });
    await ActionRegistry.updateAuthorizedMembers(ctx, {
      authorized_members: [{ id: 'CREATORS', access_right: 'view', groups_restriction_ids: [] }],
    });
    expect(draftWorkspaceEditAuthorizedMembers).toHaveBeenCalledWith(
      ctx.context, ctx.user, 'entity-id',
      [{ id: 'real-creator', access_right: 'view', groups_restriction_ids: [] }],
    );
  });

  it('skips falsy values inside ASSIGNEES array (branch 10 false)', async () => {
    // Covers `if (assigneeId)` false branch
    const { draftWorkspaceEditAuthorizedMembers } = await import('../../../src/modules/draftWorkspace/draftWorkspace-domain');
    const ctx = makeUpdateCtx({ 'object-assignee': ['', 'real-assignee'] });
    await ActionRegistry.updateAuthorizedMembers(ctx, {
      authorized_members: [{ id: 'ASSIGNEES', access_right: 'admin', groups_restriction_ids: [] }],
    });
    expect(draftWorkspaceEditAuthorizedMembers).toHaveBeenCalledWith(
      ctx.context, ctx.user, 'entity-id',
      [{ id: 'real-assignee', access_right: 'admin', groups_restriction_ids: [] }],
    );
  });

  it('skips falsy values inside PARTICIPANTS array (branch 14 false)', async () => {
    // Covers `if (participantId)` false branch
    const { draftWorkspaceEditAuthorizedMembers } = await import('../../../src/modules/draftWorkspace/draftWorkspace-domain');
    const ctx = makeUpdateCtx({ 'object-participant': ['', 'real-participant'] });
    await ActionRegistry.updateAuthorizedMembers(ctx, {
      authorized_members: [{ id: 'PARTICIPANTS', access_right: 'edit', groups_restriction_ids: [] }],
    });
    expect(draftWorkspaceEditAuthorizedMembers).toHaveBeenCalledWith(
      ctx.context, ctx.user, 'entity-id',
      [{ id: 'real-participant', access_right: 'edit', groups_restriction_ids: [] }],
    );
  });
});

describe('ActionRegistry.asyncBulkAction (null params branch)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('handles undefined params gracefully — uses {} defaults (branch 21)', async () => {
    // Covers `params ?? {}` right-hand side in asyncBulkAction
    const ctx = {
      user: { id: 'user-id' },
      entity: { id: 'entity-id', internal_id: 'entity-id', entity_type: 'Incident' },
      context: {},
      runtimeParams: {},
      pendingAsyncSlots: [] as any[],
      __createListTask: vi.fn().mockResolvedValue({ work_id: 'work-id' }),
      __workflowInstanceId: 'instance-id',
      __draftEntityIds: [],
    };
    await ActionRegistry.asyncBulkAction(ctx, undefined);
    // scope and actions are undefined/[] so the task is created with scope: undefined
    expect(ctx.__createListTask).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      expect.objectContaining({ actions: [] }),
    );
  });
});
