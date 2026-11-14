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
import { OrderingMode } from '../../../src/generated/graphql';
import { emptyFilterGroup } from '../../../src/utils/filtering/filtering-utils';

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

describe('workflow status filter (via draftWorkspacesNumber)', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.spyOn(engine, 'elCount').mockResolvedValue(0);
  });

  // DraftWorkspace carries x_opencti_workflow_id like any entity with a workflow, so the engine resolves workflow_id
  it('passes a workflow_id filter nested in a filter group to the engine as is, without loading WorkflowInstances', async () => {
    const args = {
      filters: {
        mode: 'and',
        filters: [{ key: 'entity_type', values: ['DraftWorkspace'], operator: 'eq', mode: 'or' }],
        filterGroups: [{
          mode: 'or',
          filters: [{ key: 'workflow_id', values: ['status-template-abc'], operator: 'eq', mode: 'or' }],
          filterGroups: [],
        }],
      },
    };

    await draftWorkspacesNumber(mockContext, mockUser, args);

    expect(middlewareLoader.fullEntitiesList).not.toHaveBeenCalled();
    expect(vi.mocked(engine.elCount).mock.calls[0][3]).toEqual(expect.objectContaining({ filters: args.filters }));
  });
});

describe('sort by workflow status (via findDraftWorkspacePaginated)', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.spyOn(middlewareLoader, 'pageEntitiesConnection').mockResolvedValue({ edges: [], pageInfo: { globalCount: 0 } } as any);
  });

  it('sorts natively on the projected status, without loading WorkflowInstances or every draft', async () => {
    const args: any = { first: 10, orderBy: 'workflowInstance', orderMode: OrderingMode.Desc, filters: emptyFilterGroup };

    await findDraftWorkspacePaginated(mockContext, mockUser, args);

    expect(middlewareLoader.fullEntitiesList).not.toHaveBeenCalled();
    expect(middlewareLoader.pageEntitiesConnection).toHaveBeenCalledWith(
      mockContext,
      mockUser,
      ['DraftWorkspace'],
      { ...args, orderBy: 'x_opencti_workflow_id' },
    );
  });

  it('keeps any other sort as requested', async () => {
    const args: any = { orderBy: 'name', orderMode: OrderingMode.Asc, filters: emptyFilterGroup };

    await findDraftWorkspacePaginated(mockContext, mockUser, args);

    expect(middlewareLoader.pageEntitiesConnection).toHaveBeenCalledWith(mockContext, mockUser, ['DraftWorkspace'], args);
  });
});

describe('distribution by workflow status (via draftWorkspacesDistribution)', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.spyOn(draftContextUtils, 'bypassDraftContext').mockReturnValue(mockContext);
    vi.spyOn(cacheModule, 'getEntitiesListFromCache').mockResolvedValue([
      { id: 'status-new', name: 'New' },
      { id: 'status-review', name: 'Review' },
      { id: 'status-review-local', name: 'Review' },
    ] as any);
  });

  it('aggregates the projected status and labels each bucket with its status name', async () => {
    vi.spyOn(engine, 'elAggregationCount').mockResolvedValue([
      { key: 'status-new', label: 'status-new', value: 1, count: 1 },
      { key: 'status-review', label: 'status-review', value: 3, count: 3 },
    ]);
    const args = { field: 'workflowInstance', operation: 'count', filters: emptyFilterGroup, search: 'alpha' };

    const result = await draftWorkspacesDistribution(mockContext, mockUser, args);

    expect(middlewareLoader.fullEntitiesList).not.toHaveBeenCalled();
    expect(engine.elAggregationCount).toHaveBeenCalledWith(mockContext, mockUser, expect.anything(), expect.objectContaining({
      field: 'x_opencti_workflow_id',
      types: ['DraftWorkspace'],
      filters: emptyFilterGroup,
      search: 'alpha',
    }));
    expect(result).toEqual([
      { label: 'Review', value: 3, entity: null },
      { label: 'New', value: 1, entity: null },
    ]);
  });

  it('merges statuses sharing a name and counts drafts without a known status as Unknown', async () => {
    vi.spyOn(engine, 'elAggregationCount').mockResolvedValue([
      { key: 'status-review', label: 'status-review', value: 2, count: 2 },
      { key: 'status-review-local', label: 'status-review-local', value: 1, count: 1 },
      { key: 'unknown', label: 'unknown', value: 4, count: 4 },
    ]);

    const result = await draftWorkspacesDistribution(mockContext, mockUser, { field: 'workflowInstance', order: 'asc' });

    expect(result).toEqual([
      { label: 'Review', value: 3, entity: null },
      { label: 'Unknown', value: 4, entity: null },
    ]);
  });

  it('applies the limit after sorting', async () => {
    vi.spyOn(engine, 'elAggregationCount').mockResolvedValue([
      { key: 'status-new', label: 'status-new', value: 1, count: 1 },
      { key: 'status-review', label: 'status-review', value: 3, count: 3 },
    ]);

    const result = await draftWorkspacesDistribution(mockContext, mockUser, { field: 'workflowInstance', limit: 1 });

    expect(result).toEqual([{ label: 'Review', value: 3, entity: null }]);
  });

  it('falls through to distributionEntities when field is not workflowInstance', async () => {
    const args = { field: 'draft_status', operation: 'count' };

    await draftWorkspacesDistribution(mockContext, mockUser, args);

    expect(middleware.distributionEntities).toHaveBeenCalledWith(mockContext, mockUser, ['DraftWorkspace'], args);
    expect(engine.elAggregationCount).not.toHaveBeenCalled();
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
