import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as middlewareLoader from '../../../../src/database/middleware-loader';
import { ENTITY_TYPE_WORKFLOW_INSTANCE } from '../../../../src/modules/workflow/types/workflow-types';
import * as draftContextUtils from '../../../../src/utils/draftContext';
import { WORKFLOW_INSTANCE_STATUS_FILTER } from '../../../../src/utils/filtering/filtering-constants';
import { resolveWorkflowStatusFilter } from '../../../../src/utils/filtering/workflow-status-filter';

vi.mock('../../../../src/database/middleware-loader');

const mockUser: any = { id: 'user-1' };
const mockContext: any = { user: mockUser };

describe('resolveWorkflowStatusFilter', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.spyOn(draftContextUtils, 'bypassDraftContext').mockReturnValue(mockContext);
  });

  it('returns args unchanged when there are no filters at all', async () => {
    const args = {};

    const result = await resolveWorkflowStatusFilter(mockContext, args);

    expect(result).toBe(args);
    expect(middlewareLoader.fullEntitiesList).not.toHaveBeenCalled();
  });

  it('returns args unchanged when no workflow status filter is present', async () => {
    const args = {
      filters: { mode: 'and', filters: [{ key: 'name', values: ['foo'], operator: 'eq', mode: 'or' }], filterGroups: [] },
    };

    const result = await resolveWorkflowStatusFilter(mockContext, args);

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

    const result = await resolveWorkflowStatusFilter(mockContext, args);

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

    const result = await resolveWorkflowStatusFilter(mockContext, args);

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

    const result = await resolveWorkflowStatusFilter(mockContext, args);

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

    const result = await resolveWorkflowStatusFilter(mockContext, args);

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

    const result = await resolveWorkflowStatusFilter(mockContext, args);

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

    const result = await resolveWorkflowStatusFilter(mockContext, args);

    expect(result.filters.filterGroups[0].filters).toEqual([{ key: ['id'], values: ['draft-1'], operator: 'eq', mode: 'or' }]);
  });

  it('rejects a workflow status filter with a non-equality operator', async () => {
    const args = {
      filters: {
        mode: 'and',
        filters: [{ key: WORKFLOW_INSTANCE_STATUS_FILTER, values: [], operator: 'nil', mode: 'or' }],
        filterGroups: [],
      },
    };

    await expect(resolveWorkflowStatusFilter(mockContext, args)).rejects.toThrow('Workflow status filter only supports equality operators');
    expect(middlewareLoader.fullEntitiesList).not.toHaveBeenCalled();
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

    const result = await resolveWorkflowStatusFilter(mockContext, args);

    expect(result.filters.filters[0].values).toHaveLength(5001);
  });
});
