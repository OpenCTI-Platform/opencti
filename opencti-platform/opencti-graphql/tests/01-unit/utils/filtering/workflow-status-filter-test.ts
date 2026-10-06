import { beforeEach, describe, expect, it, vi } from 'vitest';
import { logApp } from '../../../../src/config/conf';
import * as middlewareLoader from '../../../../src/database/middleware-loader';
import { ENTITY_TYPE_WORKFLOW_INSTANCE } from '../../../../src/modules/workflow/types/workflow-types';
import * as draftContextUtils from '../../../../src/utils/draftContext';
import { WORKFLOW_INSTANCE_STATUS_FILTER } from '../../../../src/utils/filtering/filtering-constants';
import { resolveWorkflowStatusFilter } from '../../../../src/utils/filtering/workflow-status-filter';

vi.mock('../../../../src/database/middleware-loader');

vi.mock('../../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../../src/config/conf')>();
  return {
    ...actual,
    logApp: {
      error: vi.fn(),
      info: vi.fn(),
      warn: vi.fn(),
    },
  };
});

const mockUser: any = { id: 'user-1' };
const mockContext: any = { user: mockUser };

describe('resolveWorkflowStatusFilter', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    vi.spyOn(draftContextUtils, 'bypassDraftContext').mockReturnValue(mockContext);
  });

  it('returns args unchanged when there are no filters at all', async () => {
    const args = {};

    const result = await resolveWorkflowStatusFilter(mockContext, mockUser, 'Incident', args);

    expect(result).toBe(args);
    expect(middlewareLoader.fullEntitiesList).not.toHaveBeenCalled();
  });

  it('returns args unchanged when no workflow status filter is present', async () => {
    const args = {
      filters: { mode: 'and', filters: [{ key: 'name', values: ['foo'], operator: 'eq', mode: 'or' }], filterGroups: [] },
    };

    const result = await resolveWorkflowStatusFilter(mockContext, mockUser, 'Incident', args);

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

    const result = await resolveWorkflowStatusFilter(mockContext, mockUser, 'Incident', args);

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

    const result = await resolveWorkflowStatusFilter(mockContext, mockUser, 'Report', args);

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

    const result = await resolveWorkflowStatusFilter(mockContext, mockUser, 'Report', args);

    expect(result.filters.filters).toEqual([
      expect.objectContaining({ key: 'name' }),
      expect.objectContaining({ key: ['id'], values: ['report-1'] }),
    ]);
  });

  it('logs a warning when the WorkflowInstance query hits its bound', async () => {
    const fiveThousandInstances = Array.from({ length: 5000 }, (_, i) => ({ entity_id: `entity-${i}` }));
    (middlewareLoader.fullEntitiesList as any).mockResolvedValue(fiveThousandInstances);
    const args = {
      filters: {
        mode: 'and',
        filters: [{ key: WORKFLOW_INSTANCE_STATUS_FILTER, values: ['status-template-abc'], operator: 'eq', mode: 'or' }],
        filterGroups: [],
      },
    };

    await resolveWorkflowStatusFilter(mockContext, mockUser, 'Incident', args);

    expect(logApp.warn).toHaveBeenCalledWith(expect.stringContaining('bound'), expect.objectContaining({ entityType: 'Incident' }));
  });
});
