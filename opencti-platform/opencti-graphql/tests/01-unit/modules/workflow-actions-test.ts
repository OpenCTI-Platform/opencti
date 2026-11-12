import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ActionDefinitions, ActionRegistry } from '../../../src/modules/workflow/registry/workflow-actions';
import { addOrganizationRestriction, removeOrganizationRestriction } from '../../../src/domain/stix';
import { controlUserConfidenceAgainstElement } from '../../../src/utils/confidence-level';
import { internalLoadById } from '../../../src/database/middleware-loader';

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
  RELATION_GRANTED_TO: 'granted',
}));

// The real schema module pulls the attribute definitions, which need the full conf
vi.mock('../../../src/schema/stixDomainObject', () => ({
  isStixDomainObjectShareableContainer: (type: string) => type === 'Report',
}));

vi.mock('../../../src/utils/confidence-level', () => ({
  controlUserConfidenceAgainstElement: vi.fn(),
}));

vi.mock('../../../src/utils/authorizedMembers', () => ({
  editAuthorizedMembers: vi.fn(),
}));

const { SYSTEM_USER_ID, WORKFLOW_MANAGER_USER_ID } = vi.hoisted(() => ({
  SYSTEM_USER_ID: '6a4b11e1-90ca-4e42-ba42-db7bc7f7d505',
  WORKFLOW_MANAGER_USER_ID: '0a9592ed-0e00-4585-a4e8-219e33f4db48',
}));

vi.mock('../../../src/utils/access', () => ({
  KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS: 'KNOWLEDGE_KNUPDATE_KNMANAGEAUTHMEMBERS',
  isInternalUser: (user: { id: string }) => [SYSTEM_USER_ID, WORKFLOW_MANAGER_USER_ID].includes(user.id),
}));

vi.mock('../../../src/domain/stix', () => ({
  addOrganizationRestriction: vi.fn(),
  removeOrganizationRestriction: vi.fn(),
}));

vi.mock('../../../src/database/middleware-loader', () => ({
  internalLoadById: vi.fn(),
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
    // The real conf loaded below pulls the vocabulary definitions, which need the real schema constants.
    vi.doMock('../../../src/schema/stixDomainObject', async (importOriginal) => importOriginal());
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
    // The real conf loaded below pulls the vocabulary definitions, which need the real schema constants.
    vi.doMock('../../../src/schema/stixDomainObject', async (importOriginal) => importOriginal());
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
    // The real conf loaded below pulls the vocabulary definitions, which need the real schema constants.
    vi.doMock('../../../src/schema/stixDomainObject', async (importOriginal) => importOriginal());
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
    // The real conf loaded below pulls the vocabulary definitions, which need the real schema constants.
    vi.doMock('../../../src/schema/stixDomainObject', async (importOriginal) => importOriginal());
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
    // The real conf loaded below pulls the vocabulary definitions, which need the real schema constants.
    vi.doMock('../../../src/schema/stixDomainObject', async (importOriginal) => importOriginal());
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
    // The real conf loaded below pulls the vocabulary definitions, which need the real schema constants.
    vi.doMock('../../../src/schema/stixDomainObject', async (importOriginal) => importOriginal());
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

// ---------------------------------------------------------------------------
// shareRequestedEntities
// ---------------------------------------------------------------------------

describe('ActionRegistry.shareRequestedEntities', () => {
  const makeRfiCtx = (
    // The form records the requesting organization and sets it as the RFI author at creation
    requestAccess: Record<string, unknown> | null = { entities: ['entity-1', 'entity-2'], members: ['org-author'] },
    entityOverrides: Record<string, unknown> = {},
  ) => ({
    user: { id: 'workflow-manager-id' },
    triggeringUser: { id: 'approver-id' },
    context: { user: { id: 'approver-id' } },
    entity: {
      id: 'rfi-id',
      internal_id: 'rfi-id',
      entity_type: 'Case-Rfi',
      'created-by': 'org-author',
      ...(requestAccess ? { x_opencti_request_access: JSON.stringify(requestAccess) } : {}),
      ...entityOverrides,
    },
  });

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(internalLoadById).mockImplementation(async (_context: any, _user: any, id: any) => ({ id, internal_id: id }) as any);
  });

  it('is a sync-only action requiring at least one organization', () => {
    const definition = ActionDefinitions.shareRequestedEntities;
    expect(definition.allowedModes).toEqual(['sync']);
    expect(definition.paramsSchema?.safeParse({ organizations: ['AUTHOR'] }).success).toBe(true);
    expect(definition.paramsSchema?.safeParse({ organizations: [] }).success).toBe(false);
  });

  it('shares every requested entity with each resolved organization', async () => {
    const ctx = makeRfiCtx();
    await ActionRegistry.shareRequestedEntities(ctx, { organizations: ['AUTHOR', 'org-extra'] });
    expect(addOrganizationRestriction).toHaveBeenCalledTimes(2);
    expect(addOrganizationRestriction).toHaveBeenNthCalledWith(1, ctx.context, ctx.triggeringUser, 'entity-1', ['org-author', 'org-extra']);
    expect(addOrganizationRestriction).toHaveBeenNthCalledWith(2, ctx.context, ctx.triggeringUser, 'entity-2', ['org-author', 'org-extra']);
  });

  it('loads and shares with the triggering user, never the workflow manager', async () => {
    const ctx = makeRfiCtx();
    await ActionRegistry.shareRequestedEntities(ctx, { organizations: ['AUTHOR'] });
    const usersUsed = [
      ...vi.mocked(internalLoadById).mock.calls.map((call) => call[1]),
      ...vi.mocked(addOrganizationRestriction).mock.calls.map((call) => call[1]),
    ];
    expect(usersUsed).toHaveLength(4);
    expect(usersUsed.every((u) => u === ctx.triggeringUser)).toBe(true);
  });

  it('refuses to share when there is no triggering user', async () => {
    const ctx = { ...makeRfiCtx(), triggeringUser: undefined };
    await expect(ActionRegistry.shareRequestedEntities(ctx, { organizations: ['AUTHOR'] })).rejects.toThrow();
    expect(internalLoadById).not.toHaveBeenCalled();
    expect(addOrganizationRestriction).not.toHaveBeenCalled();
  });

  it.each([
    ['the system user', SYSTEM_USER_ID],
    ['the workflow manager', WORKFLOW_MANAGER_USER_ID],
  ])('refuses to share when the triggering user is %s', async (_label, internalUserId) => {
    const ctx = { ...makeRfiCtx(), triggeringUser: { id: internalUserId } };
    await expect(ActionRegistry.shareRequestedEntities(ctx, { organizations: ['AUTHOR'] })).rejects.toThrow();
    expect(internalLoadById).not.toHaveBeenCalled();
    expect(addOrganizationRestriction).not.toHaveBeenCalled();
  });

  it('resolves AUTHOR to the organization recorded on the request, never the RFI author', async () => {
    const ctx = makeRfiCtx({ entities: ['entity-1'], members: ['org-requester'] }, { 'created-by': 'org-changed-by-an-editor' });
    await ActionRegistry.shareRequestedEntities(ctx, { organizations: ['AUTHOR'] });
    expect(addOrganizationRestriction).toHaveBeenCalledWith(ctx.context, ctx.triggeringUser, 'entity-1', ['org-requester']);
  });

  it('throws before sharing anything when one target has restricted_members', async () => {
    vi.mocked(internalLoadById).mockImplementation(async (_context: any, _user: any, id: any) => (
      { id, internal_id: id, ...(id === 'entity-2' ? { restricted_members: [{ id: 'member-1' }] } : {}) }
    ) as any);
    const ctx = makeRfiCtx();
    await expect(ActionRegistry.shareRequestedEntities(ctx, { organizations: ['AUTHOR'] })).rejects.toThrow();
    expect(addOrganizationRestriction).not.toHaveBeenCalled();
  });

  it('throws before sharing anything when a target cannot be loaded', async () => {
    vi.mocked(internalLoadById).mockImplementation(async (_context: any, _user: any, id: any) => (
      id === 'entity-2' ? undefined : { id, internal_id: id }
    ) as any);
    const ctx = makeRfiCtx();
    await expect(ActionRegistry.shareRequestedEntities(ctx, { organizations: ['AUTHOR'] })).rejects.toThrow();
    expect(addOrganizationRestriction).not.toHaveBeenCalled();
  });

  it('throws when the entity is not a request-access RFI', async () => {
    const notRfi = makeRfiCtx({ entities: ['entity-1'] }, { entity_type: 'Incident' });
    await expect(ActionRegistry.shareRequestedEntities(notRfi, { organizations: ['AUTHOR'] })).rejects.toThrow();
    const noRequest = makeRfiCtx(null);
    await expect(ActionRegistry.shareRequestedEntities(noRequest, { organizations: ['AUTHOR'] })).rejects.toThrow();
    expect(addOrganizationRestriction).not.toHaveBeenCalled();
  });

  it('throws a clear error when the request access data is malformed', async () => {
    const invalidJson = makeRfiCtx(null, { x_opencti_request_access: '{not json' });
    await expect(ActionRegistry.shareRequestedEntities(invalidJson, { organizations: ['AUTHOR'] })).rejects.toThrow('This RFI is not compatible');
    const noEntities = makeRfiCtx({ members: ['org-requester'] });
    await expect(ActionRegistry.shareRequestedEntities(noEntities, { organizations: ['AUTHOR'] })).rejects.toThrow('This RFI is not compatible');
    const notAnObject = makeRfiCtx(null, { x_opencti_request_access: 'null' });
    await expect(ActionRegistry.shareRequestedEntities(notAnObject, { organizations: ['AUTHOR'] })).rejects.toThrow('This RFI is not compatible');
    expect(addOrganizationRestriction).not.toHaveBeenCalled();
  });

  it('throws when no organization can be resolved', async () => {
    const ctx = makeRfiCtx({ entities: ['entity-1'] });
    await expect(ActionRegistry.shareRequestedEntities(ctx, { organizations: ['AUTHOR'] })).rejects.toThrow();
    expect(addOrganizationRestriction).not.toHaveBeenCalled();
  });

  it('resolves AUTHOR to the recorded organization on a request without RFI author', async () => {
    const ctx = makeRfiCtx({ entities: ['entity-1'], members: ['org-requester'] }, { 'created-by': undefined });
    await ActionRegistry.shareRequestedEntities(ctx, { organizations: ['AUTHOR', 'org-extra'] });
    expect(addOrganizationRestriction).toHaveBeenCalledWith(ctx.context, ctx.triggeringUser, 'entity-1', ['org-requester', 'org-extra']);
  });

  it('throws before sharing anything when the approver confidence is too low for one target', async () => {
    vi.mocked(controlUserConfidenceAgainstElement).mockImplementation((_user: any, element: any) => {
      if (element.id === 'entity-2') throw new Error('confidence');
      return true;
    });
    const ctx = makeRfiCtx();
    await expect(ActionRegistry.shareRequestedEntities(ctx, { organizations: ['AUTHOR'] })).rejects.toThrow('confidence');
    expect(addOrganizationRestriction).not.toHaveBeenCalled();
    vi.mocked(controlUserConfidenceAgainstElement).mockReset();
  });

  it('undoes the grants it added when a later share fails', async () => {
    vi.mocked(internalLoadById).mockImplementation(async (_context: any, _user: any, id: any) => (
      { id, internal_id: id, entity_type: 'Malware', ...(id === 'entity-1' ? { 'rel_granted.internal_id': ['org-extra'] } : {}) }
    ) as any);
    vi.mocked(addOrganizationRestriction).mockImplementation(async (_context: any, _user: any, id: any) => {
      if (id === 'entity-2') throw new Error('share refused');
      return {} as any;
    });
    const ctx = makeRfiCtx();
    await expect(ActionRegistry.shareRequestedEntities(ctx, { organizations: ['AUTHOR', 'org-extra'] })).rejects.toThrow('share refused');
    expect(removeOrganizationRestriction).toHaveBeenCalledTimes(1);
    expect(removeOrganizationRestriction).toHaveBeenCalledWith(ctx.context, ctx.triggeringUser, 'entity-1', ['org-author']);
    vi.mocked(addOrganizationRestriction).mockReset();
  });

  it('shares containers last, after every direct share', async () => {
    vi.mocked(internalLoadById).mockImplementation(async (_context: any, _user: any, id: any) => (
      { id, internal_id: id, entity_type: id === 'entity-1' ? 'Report' : 'Malware' }
    ) as any);
    const ctx = makeRfiCtx();
    await ActionRegistry.shareRequestedEntities(ctx, { organizations: ['AUTHOR'] });
    expect(vi.mocked(addOrganizationRestriction).mock.calls.map((call) => call[2])).toEqual(['entity-2', 'entity-1']);
  });
});
