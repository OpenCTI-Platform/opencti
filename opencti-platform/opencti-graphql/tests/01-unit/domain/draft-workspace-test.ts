import { vi, describe, it, expect, beforeEach } from 'vitest';
import { addDraftWorkspace, draftWorkspacesDistribution, draftWorkspacesNumber, findDraftWorkspacePaginated } from '../../../src/modules/draftWorkspace/draftWorkspace-domain';
import * as middleware from '../../../src/database/middleware';
import * as middlewareLoader from '../../../src/database/middleware-loader';
import * as engine from '../../../src/database/engine';
import * as draftContextUtils from '../../../src/utils/draftContext';
import * as accessModule from '../../../src/utils/authorizedMembers';
import * as telemetryManager from '../../../src/manager/telemetryManager';
import * as redis from '../../../src/database/redis';
import * as cacheModule from '../../../src/database/cache';
import { WORKFLOW_INSTANCE_STATUS_FILTER } from '../../../src/utils/filtering/filtering-constants';
import { ENTITY_TYPE_WORKFLOW_INSTANCE } from '../../../src/modules/workflow/types/workflow-types';
import { OrderingMode } from '../../../src/generated/graphql';

vi.mock('../../../src/database/middleware');
vi.mock('../../../src/database/middleware-loader');
vi.mock('../../../src/database/engine');
vi.mock('../../../src/manager/telemetryManager');
vi.mock('../../../src/database/redis');
vi.mock('../../../src/database/cache');

// Mock context and user
const mockUser: any = {
  id: 'user1',
  name: 'User One',
};
const mockContext: any = {
  user: mockUser,
};

describe('addDraftWorkspace', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.spyOn(accessModule, 'sanitizeAuthorizedMembers').mockImplementation((input) => input);
    vi.spyOn(accessModule, 'containsValidAdmin').mockResolvedValue(true);
    vi.spyOn(middleware, 'createEntity').mockResolvedValue({ id: 'draft-1', name: 'Draft 1' });
    vi.spyOn(telemetryManager, 'addDraftCreationCount').mockResolvedValue();
    vi.spyOn(redis, 'notify').mockResolvedValue(undefined);
  });

  it('should create draft workspace with sanitized authorized members', async () => {
    const input = {
      name: 'Test Draft',
      authorized_members: [
        { id: 'user2', access_right: 'view', groups_restriction_ids: [] },
        { id: 'user3', access_right: 'admin', groups_restriction_ids: ['group1'] },
      ],
    };

    // sanitized members should have empty groups restriction removed
    await addDraftWorkspace(mockContext, mockUser, input);

    expect(middleware.createEntity).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      expect.objectContaining({
        authorized_members: expect.arrayContaining([
          expect.objectContaining({ id: 'user2', access_right: 'view' }), // groups_restriction_ids implicitly removed
          expect.objectContaining({ id: 'user3', access_right: 'admin', groups_restriction_ids: ['group1'] }),
        ]),
      }),
      'DraftWorkspace',
      expect.objectContaining({ bypassMandatoryAttributes: false }),
    );
    // Ensure groups_restriction_ids is removed for user2
    const callArgs = vi.mocked(middleware.createEntity).mock.calls[0][2];
    const user2Member = callArgs.authorized_members.find((m: any) => m.id === 'user2');
    expect(user2Member.groups_restriction_ids).toBeUndefined();
  });

  it('should not throw if authorized members do not contain valid admin', async () => {
    vi.spyOn(accessModule, 'containsValidAdmin').mockResolvedValue(false);

    const input = {
      name: 'Draft No Admin',
      authorized_members: [
        { id: 'user2', access_right: 'view' },
      ],
    };

    await expect(addDraftWorkspace(mockContext, mockUser, input))
      .resolves
      .not
      .toThrow();
  });

  it('should allow creation without authorized members', async () => {
    const input = {
      name: 'Simple Draft',
    };

    await addDraftWorkspace(mockContext, mockUser, input);

    expect(middleware.createEntity).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      expect.objectContaining({
        name: 'Simple Draft',
      }),
      'DraftWorkspace',
      expect.objectContaining({ bypassMandatoryAttributes: false }),
    );
  });
});

describe('resolveWorkflowInstanceStatusFilter (via draftWorkspacesNumber)', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.spyOn(engine, 'elCount').mockResolvedValue(0);
    vi.spyOn(draftContextUtils, 'bypassDraftContext').mockReturnValue(mockContext);
  });

  it('should not call fullEntitiesList when no workflowInstanceCurrentState filter is present', async () => {
    const args = {
      filters: {
        mode: 'and',
        filters: [{ key: 'name', values: ['my-draft'], operator: 'eq', mode: 'or' }],
        filterGroups: [],
      },
    };
    await draftWorkspacesNumber(mockContext, mockUser, args);
    expect(middlewareLoader.fullEntitiesList).not.toHaveBeenCalled();
  });

  it('should replace workflowInstanceCurrentState filter with matching entity ids', async () => {
    vi.spyOn(middlewareLoader, 'fullEntitiesList').mockResolvedValue([
      { entity_id: 'draft-uuid-1' },
      { entity_id: 'draft-uuid-2' },
    ] as any);
    const args = {
      filters: {
        mode: 'and',
        filters: [{ key: WORKFLOW_INSTANCE_STATUS_FILTER, values: ['status-template-abc'], operator: 'eq', mode: 'or' }],
        filterGroups: [],
      },
    };
    await draftWorkspacesNumber(mockContext, mockUser, args);
    expect(middlewareLoader.fullEntitiesList).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      [ENTITY_TYPE_WORKFLOW_INSTANCE],
      expect.objectContaining({
        filters: expect.objectContaining({
          filters: expect.arrayContaining([
            expect.objectContaining({ key: ['currentState'], values: ['status-template-abc'] }),
          ]),
        }),
      }),
    );
    expect(engine.elCount).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      expect.anything(),
      expect.objectContaining({
        filters: expect.objectContaining({
          filters: expect.arrayContaining([
            expect.objectContaining({ key: ['id'], values: ['draft-uuid-1', 'draft-uuid-2'] }),
          ]),
        }),
      }),
    );
  });

  it('should use <no-match> fallback when no WorkflowInstance entities match the filter', async () => {
    vi.spyOn(middlewareLoader, 'fullEntitiesList').mockResolvedValue([] as any);
    const args = {
      filters: {
        mode: 'and',
        filters: [{ key: WORKFLOW_INSTANCE_STATUS_FILTER, values: ['status-template-xyz'], operator: 'eq', mode: 'or' }],
        filterGroups: [],
      },
    };
    await draftWorkspacesNumber(mockContext, mockUser, args);
    expect(engine.elCount).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      expect.anything(),
      expect.objectContaining({
        filters: expect.objectContaining({
          filters: expect.arrayContaining([
            expect.objectContaining({ key: ['id'], values: ['<no-match>'] }),
          ]),
        }),
      }),
    );
  });
});

describe('resolveSortByWorkflowInstance (via findDraftWorkspacePaginated)', () => {
  const mockDraftA = { id: 'draft-a', name: 'Alpha Draft' };
  const mockDraftB = { id: 'draft-b', name: 'Beta Draft' };
  const mockDraftC = { id: 'draft-c', name: 'Gamma Draft (no workflow)' };

  const mockWorkflowInstances = [
    { entity_id: 'draft-a', currentState: 'status-template-new' },
    { entity_id: 'draft-b', currentState: 'status-template-review' },
  ];

  const mockStatusTemplates = [
    { id: 'status-template-new', name: 'New' },
    { id: 'status-template-review', name: 'Review' },
  ];

  beforeEach(() => {
    vi.resetAllMocks();
    vi.spyOn(draftContextUtils, 'bypassDraftContext').mockReturnValue(mockContext);
  });

  it('should fall through to pageEntitiesConnection when orderBy is not workflowInstance', async () => {
    vi.spyOn(middlewareLoader, 'pageEntitiesConnection').mockResolvedValue({ edges: [], pageInfo: { globalCount: 0 } } as any);
    vi.spyOn(middlewareLoader, 'fullEntitiesList').mockResolvedValue([] as any);

    const args: any = { orderBy: 'name', orderMode: 'asc', filters: { mode: 'and', filters: [], filterGroups: [] } };
    await findDraftWorkspacePaginated(mockContext, mockUser, args);

    expect(middlewareLoader.pageEntitiesConnection).toHaveBeenCalled();
  });

  it('should sort drafts ascending by workflow status name, nulls last', async () => {
    vi.spyOn(middlewareLoader, 'fullEntitiesList')
      .mockResolvedValueOnce(mockWorkflowInstances as any) // WorkflowInstances
      .mockResolvedValueOnce([mockDraftB, mockDraftA, mockDraftC] as any); // DraftWorkspaces (unsorted)
    vi.spyOn(engine, 'elFindByIds').mockResolvedValue(mockStatusTemplates as any);

    const args: any = { first: 10, orderBy: 'workflowInstance', orderMode: 'asc', filters: { mode: 'and', filters: [], filterGroups: [] } };
    const result = await findDraftWorkspacePaginated(mockContext, mockUser, args);

    const ids = result.edges.map((e: any) => e.node.id);
    expect(ids).toEqual(['draft-a', 'draft-b', 'draft-c']); // New < Review, then no-workflow last
  });

  it('should sort drafts descending by workflow status name, nulls last', async () => {
    vi.spyOn(middlewareLoader, 'fullEntitiesList')
      .mockResolvedValueOnce(mockWorkflowInstances as any)
      .mockResolvedValueOnce([mockDraftA, mockDraftB, mockDraftC] as any);
    vi.spyOn(engine, 'elFindByIds').mockResolvedValue(mockStatusTemplates as any);

    const args: any = { first: 10, orderBy: 'workflowInstance', orderMode: 'desc', filters: { mode: 'and', filters: [], filterGroups: [] } };
    const result = await findDraftWorkspacePaginated(mockContext, mockUser, args);

    const ids = result.edges.map((e: any) => e.node.id);
    expect(ids).toEqual(['draft-b', 'draft-a', 'draft-c']); // Review > New, then no-workflow last
  });

  it('should set hasNextPage=true when more results exist beyond the page', async () => {
    vi.spyOn(middlewareLoader, 'fullEntitiesList')
      .mockResolvedValueOnce(mockWorkflowInstances as any)
      .mockResolvedValueOnce([mockDraftA, mockDraftB, mockDraftC] as any);
    vi.spyOn(engine, 'elFindByIds').mockResolvedValue(mockStatusTemplates as any);

    const args: any = { first: 2, orderBy: 'workflowInstance', orderMode: 'asc', filters: { mode: 'and', filters: [], filterGroups: [] } };
    const result = await findDraftWorkspacePaginated(mockContext, mockUser, args);

    expect(result.edges).toHaveLength(2);
    expect(result.pageInfo.hasNextPage).toBe(true);
    expect(result.pageInfo.globalCount).toBe(3);
  });

  it('should paginate correctly using the after cursor', async () => {
    vi.spyOn(middlewareLoader, 'fullEntitiesList')
      .mockResolvedValueOnce(mockWorkflowInstances as any)
      .mockResolvedValueOnce([mockDraftA, mockDraftB, mockDraftC] as any);
    vi.spyOn(engine, 'elFindByIds').mockResolvedValue(mockStatusTemplates as any);

    // First page
    const firstArgs: any = { first: 2, orderBy: 'workflowInstance', orderMode: 'asc', filters: { mode: 'and', filters: [], filterGroups: [] } };
    const firstPage = await findDraftWorkspacePaginated(mockContext, mockUser, firstArgs);
    const afterCursor = firstPage.pageInfo.endCursor;

    // Reset mocks for second call
    vi.spyOn(middlewareLoader, 'fullEntitiesList')
      .mockResolvedValueOnce(mockWorkflowInstances as any)
      .mockResolvedValueOnce([mockDraftA, mockDraftB, mockDraftC] as any);

    const secondArgs: any = { first: 2, orderBy: 'workflowInstance', orderMode: 'asc', after: afterCursor, filters: { mode: 'and', filters: [], filterGroups: [] } };
    const secondPage = await findDraftWorkspacePaginated(mockContext, mockUser, secondArgs);

    expect(secondPage.edges).toHaveLength(1);
    expect(secondPage.edges[0].node.id).toBe('draft-c');
    expect(secondPage.pageInfo.hasNextPage).toBe(false);
  });

  it('should return empty result when there are no drafts', async () => {
    vi.spyOn(middlewareLoader, 'fullEntitiesList')
      .mockResolvedValueOnce([] as any) // no WorkflowInstances
      .mockResolvedValueOnce([] as any); // no DraftWorkspaces
    vi.spyOn(engine, 'elFindByIds').mockResolvedValue([] as any);

    const args: any = { first: 10, orderBy: 'workflowInstance', orderMode: 'asc', filters: { mode: 'and', filters: [], filterGroups: [] } };
    const result = await findDraftWorkspacePaginated(mockContext, mockUser, args);

    expect(result.edges).toHaveLength(0);
    expect(result.pageInfo.hasNextPage).toBe(false);
    expect(result.pageInfo.globalCount).toBe(0);
  });
});

describe('resolveWorkflowInstanceDistribution (via draftWorkspacesDistribution)', () => {
  const mockDraftA = { id: 'draft-a', name: 'Alpha Draft' };
  const mockDraftB = { id: 'draft-b', name: 'Beta Draft' };
  const mockDraftC = { id: 'draft-c', name: 'Gamma Draft (no workflow)' };

  const mockWorkflowInstances = [
    { entity_id: 'draft-a', currentState: 'status-template-new' },
    { entity_id: 'draft-b', currentState: 'status-template-review' },
  ];

  const mockStatusTemplates = [
    { id: 'status-template-new', name: 'New' },
    { id: 'status-template-review', name: 'Review' },
  ];

  const baseArgs: any = {
    field: 'workflowInstance',
    operation: 'count',
    filters: { mode: 'and', filters: [], filterGroups: [] },
  };

  beforeEach(() => {
    vi.resetAllMocks();
    vi.spyOn(draftContextUtils, 'bypassDraftContext').mockReturnValue(mockContext);
  });

  it('should fall through to distributionEntities when field is not workflowInstance', async () => {
    vi.spyOn(middleware, 'distributionEntities').mockResolvedValue([]);

    const args: any = { ...baseArgs, field: 'draft_status' };
    await draftWorkspacesDistribution(mockContext, mockUser, args);

    expect(middleware.distributionEntities).toHaveBeenCalled();
    expect(middlewareLoader.fullEntitiesList).not.toHaveBeenCalled();
  });

  it('should group drafts by workflow status name descending by default', async () => {
    vi.spyOn(middlewareLoader, 'fullEntitiesList')
      .mockResolvedValueOnce(mockWorkflowInstances as any) // WorkflowInstances
      .mockResolvedValueOnce([mockDraftA, mockDraftB, mockDraftC] as any); // DraftWorkspaces
    vi.spyOn(engine, 'elFindByIds').mockResolvedValue(mockStatusTemplates as any);

    const result = await draftWorkspacesDistribution(mockContext, mockUser, { ...baseArgs, limit: 10, order: 'desc' });

    expect(result).toHaveLength(3);
    // desc by count: Review=1, New=1, then Unknown=1 — stable sort, New before Review alphabetically but desc by count they're equal
    const labels = result.map((r: any) => r.label);
    expect(labels).toContain('New');
    expect(labels).toContain('Review');
    expect(labels).toContain('Unknown');
    expect(result.every((r: any) => r.value === 1)).toBe(true);
    expect(result.every((r: any) => r.entity === null)).toBe(true);
  });

  it('should group multiple drafts under the same status', async () => {
    const allDraftsWithSameStatus = [
      { id: 'draft-a' },
      { id: 'draft-b' },
      { id: 'draft-c' },
    ];
    vi.spyOn(middlewareLoader, 'fullEntitiesList')
      .mockResolvedValueOnce([
        { entity_id: 'draft-a', currentState: 'status-template-new' },
        { entity_id: 'draft-b', currentState: 'status-template-new' },
      ] as any)
      .mockResolvedValueOnce(allDraftsWithSameStatus as any);
    vi.spyOn(engine, 'elFindByIds').mockResolvedValue([{ id: 'status-template-new', name: 'New' }] as any);

    const result = await draftWorkspacesDistribution(mockContext, mockUser, { ...baseArgs, limit: 10 });

    const newEntry = result.find((r: any) => r.label === 'New');
    const unknownEntry = result.find((r: any) => r.label === 'Unknown');
    expect(newEntry?.value).toBe(2);
    expect(unknownEntry?.value).toBe(1);
  });

  it('should label all drafts as Unknown when no WorkflowInstances exist', async () => {
    vi.spyOn(middlewareLoader, 'fullEntitiesList')
      .mockResolvedValueOnce([] as any) // no WorkflowInstances
      .mockResolvedValueOnce([mockDraftA, mockDraftB] as any);
    vi.spyOn(engine, 'elFindByIds').mockResolvedValue([] as any);

    const result = await draftWorkspacesDistribution(mockContext, mockUser, { ...baseArgs, limit: 10 });

    expect(result).toHaveLength(1);
    expect(result[0].label).toBe('Unknown');
    expect(result[0].value).toBe(2);
  });

  it('should return empty array when there are no drafts', async () => {
    vi.spyOn(middlewareLoader, 'fullEntitiesList')
      .mockResolvedValueOnce([] as any)
      .mockResolvedValueOnce([] as any);
    vi.spyOn(engine, 'elFindByIds').mockResolvedValue([] as any);

    const result = await draftWorkspacesDistribution(mockContext, mockUser, { ...baseArgs, limit: 10 });

    expect(result).toHaveLength(0);
  });

  it('should respect the limit parameter', async () => {
    vi.spyOn(middlewareLoader, 'fullEntitiesList')
      .mockResolvedValueOnce(mockWorkflowInstances as any)
      .mockResolvedValueOnce([mockDraftA, mockDraftB, mockDraftC] as any);
    vi.spyOn(engine, 'elFindByIds').mockResolvedValue(mockStatusTemplates as any);

    const result = await draftWorkspacesDistribution(mockContext, mockUser, { ...baseArgs, limit: 2 });

    expect(result).toHaveLength(2);
  });
});

describe('resolveSortByRefUsers (via findDraftWorkspacePaginated with objectAssignee/objectParticipant)', () => {
  const mockUsers = [
    { internal_id: 'user-florian', name: 'Florian' },
    { internal_id: 'user-vi', name: 'Vi' },
  ];

  const mockDraftWithFlorian: any = { id: 'draft-florian', name: 'Draft Florian', 'object-assignee': ['user-florian'] };
  const mockDraftWithVi: any = { id: 'draft-vi', name: 'Draft Vi', 'object-assignee': ['user-vi'] };
  const mockDraftNoAssignee: any = { id: 'draft-empty', name: 'Draft No Assignee', 'object-assignee': [] };

  beforeEach(() => {
    vi.resetAllMocks();
    vi.spyOn(draftContextUtils, 'bypassDraftContext').mockReturnValue(mockContext);
    vi.spyOn(cacheModule, 'getEntitiesListFromCache').mockResolvedValue(mockUsers as any);
  });

  it('should sort by objectAssignee ASC: Florian first, empty last', async () => {
    vi.spyOn(middlewareLoader, 'fullEntitiesList').mockResolvedValue([mockDraftWithVi, mockDraftWithFlorian, mockDraftNoAssignee] as any);

    const result = await findDraftWorkspacePaginated(mockContext, mockUser, {
      orderBy: 'objectAssignee' as any,
      orderMode: OrderingMode.Asc,
      first: 10,
    });

    const ids = result.edges.map((e: any) => e.node.id);
    expect(ids).toEqual(['draft-florian', 'draft-vi', 'draft-empty']);
  });

  it('should sort by objectAssignee DESC: empty first, then Vi (reverse alpha)', async () => {
    vi.spyOn(middlewareLoader, 'fullEntitiesList').mockResolvedValue([mockDraftWithFlorian, mockDraftNoAssignee, mockDraftWithVi] as any);

    const result = await findDraftWorkspacePaginated(mockContext, mockUser, {
      orderBy: 'objectAssignee' as any,
      orderMode: OrderingMode.Desc,
      first: 10,
    });

    const ids = result.edges.map((e: any) => e.node.id);
    expect(ids).toEqual(['draft-empty', 'draft-vi', 'draft-florian']);
  });

  it('should sort by objectParticipant ASC using object-participant relation field', async () => {
    const draftWithParticipant: any = { id: 'draft-p', name: 'Draft P', 'object-participant': ['user-florian'] };
    const draftNoParticipant: any = { id: 'draft-np', name: 'Draft NP', 'object-participant': [] };
    vi.spyOn(middlewareLoader, 'fullEntitiesList').mockResolvedValue([draftNoParticipant, draftWithParticipant] as any);

    const result = await findDraftWorkspacePaginated(mockContext, mockUser, {
      orderBy: 'objectParticipant' as any,
      orderMode: OrderingMode.Asc,
      first: 10,
    });

    const ids = result.edges.map((e: any) => e.node.id);
    expect(ids).toEqual(['draft-p', 'draft-np']);
  });

  it('should return empty pagination when there are no drafts', async () => {
    vi.spyOn(middlewareLoader, 'fullEntitiesList').mockResolvedValue([] as any);

    const result = await findDraftWorkspacePaginated(mockContext, mockUser, {
      orderBy: 'objectAssignee' as any,
      orderMode: OrderingMode.Asc,
      first: 10,
    });

    expect(result.edges).toHaveLength(0);
    expect(result.pageInfo.globalCount).toBe(0);
  });

  it('should handle drafts where assignee id is not in the user cache (treats as no assignee)', async () => {
    const draftUnknownUser: any = { id: 'draft-unknown', name: 'Draft Unknown', 'object-assignee': ['user-unknown-id'] };
    vi.spyOn(middlewareLoader, 'fullEntitiesList').mockResolvedValue([mockDraftWithFlorian, draftUnknownUser] as any);

    const result = await findDraftWorkspacePaginated(mockContext, mockUser, {
      orderBy: 'objectAssignee' as any,
      orderMode: OrderingMode.Asc,
      first: 10,
    });

    const ids = result.edges.map((e: any) => e.node.id);
    // Florian (known user) sorts first ASC; unknown user id treated as no-assignee, sorts last
    expect(ids[0]).toBe('draft-florian');
    expect(ids[1]).toBe('draft-unknown');
  });
});
