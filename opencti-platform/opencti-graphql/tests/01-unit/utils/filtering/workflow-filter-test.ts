import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as cacheModule from '../../../../src/database/cache';
import { adaptFilterToWorkflowFilterKey } from '../../../../src/utils/filtering/filtering-completeSpecialFilterKeys';
import { WORKFLOW_FILTER, WORKFLOW_INSTANCE_STATUS_FILTER } from '../../../../src/utils/filtering/filtering-constants';
import { FilterMode, FilterOperator } from '../../../../src/generated/graphql';
import type { Filter } from '../../../../src/generated/graphql';

const CONTEXT = {} as any;
const USER = { id: 'user-1' } as any;

const statusFilter = (key: string, operator: FilterOperator, values: string[]): Filter => ({ key: [key], values, operator, mode: FilterMode.Or });

describe('adaptFilterToWorkflowFilterKey', () => {
  beforeEach(() => {
    vi.spyOn(cacheModule, 'getEntitiesListFromCache').mockResolvedValue([
      { id: 'status-draft-review', internal_id: 'status-draft-review', template_id: 'template-review', type: 'DraftWorkspace' },
      { id: 'status-report-review', internal_id: 'status-report-review', template_id: 'template-review', type: 'Report' },
      { id: 'status-draft-done', internal_id: 'status-draft-done', template_id: 'template-done', type: 'DraftWorkspace' },
    ] as any);
  });

  it('matches a status template through every status built on it', async () => {
    const { newFilterGroup } = await adaptFilterToWorkflowFilterKey(CONTEXT, USER, statusFilter(WORKFLOW_FILTER, FilterOperator.Eq, ['template-review']));

    expect(newFilterGroup?.filters).toEqual([
      { key: ['x_opencti_workflow_id'], values: ['status-draft-review', 'status-report-review'], mode: FilterMode.Or, operator: FilterOperator.Eq },
    ]);
  });

  // Draft filters saved before DraftWorkspace carried x_opencti_workflow_id use the old key
  it('resolves the deprecated workflowInstanceCurrentState key exactly like workflow_id', async () => {
    for (const operator of [FilterOperator.Eq, FilterOperator.NotEq, FilterOperator.Nil, FilterOperator.NotNil]) {
      const values = operator === FilterOperator.Eq || operator === FilterOperator.NotEq ? ['template-done'] : [];
      const legacy = await adaptFilterToWorkflowFilterKey(CONTEXT, USER, statusFilter(WORKFLOW_INSTANCE_STATUS_FILTER, operator, values));
      const current = await adaptFilterToWorkflowFilterKey(CONTEXT, USER, statusFilter(WORKFLOW_FILTER, operator, values));
      expect(legacy.newFilterGroup).toEqual(current.newFilterGroup);
      expect(legacy.newFilter?.key).toEqual(current.newFilter?.key);
    }
  });
});
