import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as middlewareLoader from '../../../../src/database/middleware-loader';
import { ENTITY_TYPE_DRAFT_WORKSPACE } from '../../../../src/modules/draftWorkspace/draftWorkspace-types';
import * as workflowDomain from '../../../../src/modules/workflow/domain/workflow-domain';
import { ENTITY_TYPE_WORKFLOW_INSTANCE } from '../../../../src/modules/workflow/types/workflow-types';
import * as draftContextUtils from '../../../../src/utils/draftContext';
import { WORKFLOW_INSTANCE_STATUS_FILTER } from '../../../../src/utils/filtering/filtering-constants';
import { MAX_WORKFLOW_STATUS_FILTERS, resolveWorkflowStatusFilter } from '../../../../src/utils/filtering/workflow-status-filter';

vi.mock('../../../../src/database/middleware-loader');
vi.mock('../../../../src/modules/workflow/domain/workflow-domain', () => ({ getWorkflowDefaultState: vi.fn() }));

const mockUser: any = { id: 'user-1' };
const mockContext: any = { user: mockUser };

describe('resolveWorkflowStatusFilter', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.spyOn(draftContextUtils, 'bypassDraftContext').mockReturnValue(mockContext);
    // A published workflow whose initial state none of the tests below filter on, unless stated.
    (workflowDomain.getWorkflowDefaultState as any).mockResolvedValue({ initialState: 'status-template-initial' });
  });

  it('returns args unchanged when there are no filters at all', async () => {
    const args = {};

    const result = await resolveWorkflowStatusFilter(mockContext, args, ENTITY_TYPE_DRAFT_WORKSPACE);

    expect(result).toBe(args);
    expect(middlewareLoader.fullEntitiesList).not.toHaveBeenCalled();
  });

  it('returns args unchanged when no workflow status filter is present', async () => {
    const args = {
      filters: { mode: 'and', filters: [{ key: 'name', values: ['foo'], operator: 'eq', mode: 'or' }], filterGroups: [] },
    };

    const result = await resolveWorkflowStatusFilter(mockContext, args, ENTITY_TYPE_DRAFT_WORKSPACE);

    expect(result).toBe(args);
    expect(middlewareLoader.fullEntitiesList).not.toHaveBeenCalled();
  });

  it('replaces the workflow status filter with an id filter on matching entities', async () => {
    (middlewareLoader.fullEntitiesList as any).mockResolvedValue([
      { entity_id: 'incident-1' },
      { entity_id: 'incident-2' },
    ]);
    const args = {
      filters: {
        mode: 'and',
        filters: [{ key: WORKFLOW_INSTANCE_STATUS_FILTER, values: ['status-template-abc'], operator: 'eq', mode: 'or' }],
        filterGroups: [],
      },
    };

    const result = await resolveWorkflowStatusFilter(mockContext, args, ENTITY_TYPE_DRAFT_WORKSPACE);

    expect(middlewareLoader.fullEntitiesList).toHaveBeenCalledWith(
      mockContext,
      mockUser,
      [ENTITY_TYPE_WORKFLOW_INSTANCE],
      expect.objectContaining({
        first: 5000,
        filters: expect.objectContaining({
          filters: expect.arrayContaining([
            expect.objectContaining({ key: ['currentState'], values: ['status-template-abc'] }),
          ]),
        }),
      }),
    );
    expect(result.filters.filters).toEqual([
      expect.objectContaining({ key: ['id'], values: ['incident-1', 'incident-2'] }),
    ]);
  });

  it('uses the <no-match> sentinel when no WorkflowInstance matches', async () => {
    (middlewareLoader.fullEntitiesList as any).mockResolvedValue([]);
    const args = {
      filters: {
        mode: 'and',
        filters: [{ key: WORKFLOW_INSTANCE_STATUS_FILTER, values: ['status-template-xyz'], operator: 'eq', mode: 'or' }],
        filterGroups: [],
      },
    };

    const result = await resolveWorkflowStatusFilter(mockContext, args, ENTITY_TYPE_DRAFT_WORKSPACE);

    expect(result.filters.filters).toEqual([
      expect.objectContaining({ key: ['id'], values: ['<no-match>'] }),
    ]);
  });

  it('preserves unrelated filters alongside the resolved id filter', async () => {
    (middlewareLoader.fullEntitiesList as any).mockResolvedValue([{ entity_id: 'report-1' }]);
    const args = {
      filters: {
        mode: 'and',
        filters: [
          { key: 'name', values: ['foo'], operator: 'eq', mode: 'or' },
          { key: WORKFLOW_INSTANCE_STATUS_FILTER, values: ['status-template-abc'], operator: 'eq', mode: 'or' },
        ],
        filterGroups: [],
      },
    };

    const result = await resolveWorkflowStatusFilter(mockContext, args, ENTITY_TYPE_DRAFT_WORKSPACE);

    expect(result.filters.filters).toEqual([
      expect.objectContaining({ key: 'name' }),
      expect.objectContaining({ key: ['id'], values: ['report-1'] }),
    ]);
  });

  it('keeps the caller mode: with mode or, the id filter is OR-ed like the status filter it replaces', async () => {
    (middlewareLoader.fullEntitiesList as any).mockResolvedValue([{ entity_id: 'draft-1' }]);
    const args = {
      filters: {
        mode: 'or',
        filters: [
          { key: WORKFLOW_INSTANCE_STATUS_FILTER, values: ['status-template-abc'], operator: 'eq', mode: 'or' },
          { key: 'name', values: ['foo'], operator: 'eq', mode: 'or' },
        ],
        filterGroups: [],
      },
    };

    const result = await resolveWorkflowStatusFilter(mockContext, args, ENTITY_TYPE_DRAFT_WORKSPACE);

    expect(result.filters.mode).toBe('or');
    expect(result.filters.filters).toEqual([
      { key: ['id'], values: ['draft-1'], operator: 'eq', mode: 'or' },
      expect.objectContaining({ key: 'name' }),
    ]);
  });

  it('excludes the matching entities for a not_eq workflow status filter', async () => {
    (middlewareLoader.fullEntitiesList as any).mockResolvedValue([{ entity_id: 'draft-1' }]);
    const args = {
      filters: {
        mode: 'and',
        filters: [{ key: WORKFLOW_INSTANCE_STATUS_FILTER, values: ['status-template-abc'], operator: 'not_eq', mode: 'and' }],
        filterGroups: [],
      },
    };

    const result = await resolveWorkflowStatusFilter(mockContext, args, ENTITY_TYPE_DRAFT_WORKSPACE);

    expect(result.filters.filters).toEqual([{ key: ['id'], values: ['draft-1'], operator: 'not_eq', mode: 'and' }]);
  });

  it('resolves workflow status filters nested in filter groups', async () => {
    (middlewareLoader.fullEntitiesList as any).mockResolvedValue([{ entity_id: 'draft-1' }]);
    const args = {
      filters: {
        mode: 'and',
        filters: [],
        filterGroups: [{
          mode: 'or',
          filters: [{ key: WORKFLOW_INSTANCE_STATUS_FILTER, values: ['status-template-abc'], operator: 'eq', mode: 'or' }],
          filterGroups: [],
        }],
      },
    };

    const result = await resolveWorkflowStatusFilter(mockContext, args, ENTITY_TYPE_DRAFT_WORKSPACE);

    expect(result.filters.filterGroups[0].filters).toEqual([{ key: ['id'], values: ['draft-1'], operator: 'eq', mode: 'or' }]);
  });

  describe('entities without a WorkflowInstance, shown in the initial state', () => {
    const statusFilterArgs = (operator: string, values: string[]) => ({
      filters: {
        mode: 'and',
        filters: [{ key: WORKFLOW_INSTANCE_STATUS_FILTER, values, operator, mode: 'or' }],
        filterGroups: [],
      },
    });

    it('matches no entity for a nil filter: every entity has a status under a published workflow', async () => {
      const result = await resolveWorkflowStatusFilter(mockContext, statusFilterArgs('nil', []), ENTITY_TYPE_DRAFT_WORKSPACE);

      expect(workflowDomain.getWorkflowDefaultState).toHaveBeenCalledWith(mockContext, mockUser, ENTITY_TYPE_DRAFT_WORKSPACE);
      expect(middlewareLoader.fullEntitiesList).not.toHaveBeenCalled();
      expect(result.filters.filters).toEqual([{ key: ['id'], values: ['<no-match>'], operator: 'eq', mode: 'or' }]);
    });

    it('matches every entity for a not_nil filter under a published workflow', async () => {
      const result = await resolveWorkflowStatusFilter(mockContext, statusFilterArgs('not_nil', []), ENTITY_TYPE_DRAFT_WORKSPACE);

      expect(middlewareLoader.fullEntitiesList).not.toHaveBeenCalled();
      expect(result.filters.filters).toEqual([{ key: ['id'], values: ['<no-match>'], operator: 'not_eq', mode: 'and' }]);
    });

    it('keeps entities without an instance when filtering on the initial state', async () => {
      (middlewareLoader.fullEntitiesList as any).mockResolvedValue([{ entity_id: 'draft-elsewhere' }]);

      const result = await resolveWorkflowStatusFilter(mockContext, statusFilterArgs('eq', ['status-template-initial']), ENTITY_TYPE_DRAFT_WORKSPACE);

      expect(middlewareLoader.fullEntitiesList).toHaveBeenCalledWith(
        mockContext,
        mockUser,
        [ENTITY_TYPE_WORKFLOW_INSTANCE],
        expect.objectContaining({
          filters: expect.objectContaining({
            filters: [
              { key: ['currentState'], values: [], operator: 'not_nil', mode: 'or' },
              { key: ['currentState'], values: ['status-template-initial'], operator: 'not_eq', mode: 'and' },
            ],
          }),
        }),
      );
      expect(result.filters.filters).toEqual([{ key: ['id'], values: ['draft-elsewhere'], operator: 'not_eq', mode: 'and' }]);
    });

    it('drops entities without an instance when excluding the initial state', async () => {
      (middlewareLoader.fullEntitiesList as any).mockResolvedValue([{ entity_id: 'draft-elsewhere' }]);

      const result = await resolveWorkflowStatusFilter(mockContext, statusFilterArgs('not_eq', ['status-template-initial']), ENTITY_TYPE_DRAFT_WORKSPACE);

      expect(result.filters.filters).toEqual([{ key: ['id'], values: ['draft-elsewhere'], operator: 'eq', mode: 'or' }]);
    });

    it('resolves nil and not_nil from the instances when the workflow has no initial state', async () => {
      (workflowDomain.getWorkflowDefaultState as any).mockResolvedValue({ initialState: null });
      (middlewareLoader.fullEntitiesList as any).mockResolvedValue([{ entity_id: 'draft-1' }]);

      const nilResult = await resolveWorkflowStatusFilter(mockContext, statusFilterArgs('nil', []), ENTITY_TYPE_DRAFT_WORKSPACE);
      const notNilResult = await resolveWorkflowStatusFilter(mockContext, statusFilterArgs('not_nil', []), ENTITY_TYPE_DRAFT_WORKSPACE);

      expect(middlewareLoader.fullEntitiesList).toHaveBeenCalledWith(
        mockContext,
        mockUser,
        [ENTITY_TYPE_WORKFLOW_INSTANCE],
        expect.objectContaining({
          filters: expect.objectContaining({ filters: [{ key: ['currentState'], values: [], operator: 'not_nil', mode: 'or' }] }),
        }),
      );
      expect(nilResult.filters.filters).toEqual([{ key: ['id'], values: ['draft-1'], operator: 'not_eq', mode: 'and' }]);
      expect(notNilResult.filters.filters).toEqual([{ key: ['id'], values: ['draft-1'], operator: 'eq', mode: 'or' }]);
    });

    it('ignores instances when the type has no published workflow: no entity shows a status', async () => {
      (workflowDomain.getWorkflowDefaultState as any).mockResolvedValue(null);

      const eqResult = await resolveWorkflowStatusFilter(mockContext, statusFilterArgs('eq', ['status-template-abc']), ENTITY_TYPE_DRAFT_WORKSPACE);
      const nilResult = await resolveWorkflowStatusFilter(mockContext, statusFilterArgs('nil', []), ENTITY_TYPE_DRAFT_WORKSPACE);

      expect(middlewareLoader.fullEntitiesList).not.toHaveBeenCalled();
      expect(eqResult.filters.filters).toEqual([{ key: ['id'], values: ['<no-match>'], operator: 'eq', mode: 'or' }]);
      expect(nilResult.filters.filters).toEqual([{ key: ['id'], values: ['<no-match>'], operator: 'not_eq', mode: 'and' }]);
    });
  });

  it('rejects a workflow status filter with an unsupported operator', async () => {
    const args = {
      filters: {
        mode: 'and',
        filters: [{ key: WORKFLOW_INSTANCE_STATUS_FILTER, values: ['status-template-abc'], operator: 'gt', mode: 'or' }],
        filterGroups: [],
      },
    };

    await expect(resolveWorkflowStatusFilter(mockContext, args, ENTITY_TYPE_DRAFT_WORKSPACE)).rejects.toThrow('Workflow status filter only supports equality and empty operators');
    expect(middlewareLoader.fullEntitiesList).not.toHaveBeenCalled();
  });

  describe('bounding the WorkflowInstance lookups of one filter tree', () => {
    const statusFilter = (values: string[], operator = 'eq') => ({ key: WORKFLOW_INSTANCE_STATUS_FILTER, values, operator, mode: 'or' });
    // One nested group per status filter, the shape that used to fan out into one concurrent scan each.
    const nestedArgs = (statusFilters: any[]) => ({
      filters: {
        mode: 'or',
        filters: [],
        filterGroups: statusFilters.map((f) => ({ mode: 'and', filters: [f], filterGroups: [] })),
      },
    });

    it('runs one lookup for identical status filters spread over nested groups', async () => {
      (middlewareLoader.fullEntitiesList as any).mockResolvedValue([{ entity_id: 'draft-1' }]);
      const args = nestedArgs(Array.from({ length: MAX_WORKFLOW_STATUS_FILTERS }, () => statusFilter(['status-template-abc'])));

      const result = await resolveWorkflowStatusFilter(mockContext, args, ENTITY_TYPE_DRAFT_WORKSPACE);

      expect(middlewareLoader.fullEntitiesList).toHaveBeenCalledTimes(1);
      expect(result.filters.filterGroups).toHaveLength(MAX_WORKFLOW_STATUS_FILTERS);
      result.filters.filterGroups.forEach((g: any) => {
        expect(g.filters).toEqual([{ key: ['id'], values: ['draft-1'], operator: 'eq', mode: 'or' }]);
      });
    });

    it('shares the lookup between the same states listed in another order and between eq and not_eq', async () => {
      (middlewareLoader.fullEntitiesList as any).mockResolvedValue([{ entity_id: 'draft-1' }]);
      const args = nestedArgs([
        statusFilter(['status-template-abc', 'status-template-def']),
        statusFilter(['status-template-def', 'status-template-abc']),
        statusFilter(['status-template-abc', 'status-template-def'], 'not_eq'),
      ]);

      const result = await resolveWorkflowStatusFilter(mockContext, args, ENTITY_TYPE_DRAFT_WORKSPACE);

      expect(middlewareLoader.fullEntitiesList).toHaveBeenCalledTimes(1);
      expect(result.filters.filterGroups.map((g: any) => g.filters[0])).toEqual([
        { key: ['id'], values: ['draft-1'], operator: 'eq', mode: 'or' },
        { key: ['id'], values: ['draft-1'], operator: 'eq', mode: 'or' },
        { key: ['id'], values: ['draft-1'], operator: 'not_eq', mode: 'and' },
      ]);
    });

    it('still runs one lookup per distinct state set, each replaced where it stands', async () => {
      (middlewareLoader.fullEntitiesList as any).mockImplementation(async (_ctx: any, _user: any, _types: any, opts: any) => {
        const [state] = opts.filters.filters[0].values;
        return [{ entity_id: `draft-in-${state}` }];
      });
      const args = nestedArgs([statusFilter(['status-template-abc']), statusFilter(['status-template-def'])]);

      const result = await resolveWorkflowStatusFilter(mockContext, args, ENTITY_TYPE_DRAFT_WORKSPACE);

      expect(middlewareLoader.fullEntitiesList).toHaveBeenCalledTimes(2);
      expect(result.filters.filterGroups.map((g: any) => g.filters[0].values)).toEqual([
        ['draft-in-status-template-abc'],
        ['draft-in-status-template-def'],
      ]);
    });

    it(`accepts up to ${MAX_WORKFLOW_STATUS_FILTERS} status filters in one tree`, async () => {
      (middlewareLoader.fullEntitiesList as any).mockResolvedValue([]);
      const args = nestedArgs(Array.from({ length: MAX_WORKFLOW_STATUS_FILTERS }, (_, i) => statusFilter([`status-template-${i}`])));

      await resolveWorkflowStatusFilter(mockContext, args, ENTITY_TYPE_DRAFT_WORKSPACE);

      expect(middlewareLoader.fullEntitiesList).toHaveBeenCalledTimes(MAX_WORKFLOW_STATUS_FILTERS);
    });

    it('rejects a tree with more status filters than the limit before any lookup', async () => {
      // Identical filters count too: the limit bounds the tree, not only the lookups left after sharing.
      const args = nestedArgs(Array.from({ length: MAX_WORKFLOW_STATUS_FILTERS + 1 }, () => statusFilter(['status-template-abc'])));

      await expect(resolveWorkflowStatusFilter(mockContext, args, ENTITY_TYPE_DRAFT_WORKSPACE)).rejects.toThrow('Too many workflow status filters');
      expect(workflowDomain.getWorkflowDefaultState).not.toHaveBeenCalled();
      expect(middlewareLoader.fullEntitiesList).not.toHaveBeenCalled();
    });
  });

  it('does not cap the resolved id list', async () => {
    const instances = Array.from({ length: 5001 }, (_, i) => ({ entity_id: `entity-${i}` }));
    (middlewareLoader.fullEntitiesList as any).mockResolvedValue(instances);
    const args = {
      filters: {
        mode: 'and',
        filters: [{ key: WORKFLOW_INSTANCE_STATUS_FILTER, values: ['status-template-abc'], operator: 'eq', mode: 'or' }],
        filterGroups: [],
      },
    };

    const result = await resolveWorkflowStatusFilter(mockContext, args, ENTITY_TYPE_DRAFT_WORKSPACE);

    expect(result.filters.filters[0].values).toHaveLength(5001);
  });
});
