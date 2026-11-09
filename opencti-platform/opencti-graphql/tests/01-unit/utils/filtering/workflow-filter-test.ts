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
  describe('the deprecated workflowInstanceCurrentState key', () => {
    const legacyFilter = (operator: FilterOperator, values: string[], mode = FilterMode.Or): Filter => ({ key: [WORKFLOW_INSTANCE_STATUS_FILTER], values, operator, mode });

    it('resolves eq, nil and not_nil exactly like workflow_id', async () => {
      for (const operator of [FilterOperator.Eq, FilterOperator.Nil, FilterOperator.NotNil]) {
        const values = operator === FilterOperator.Eq ? ['template-done'] : [];
        const legacy = await adaptFilterToWorkflowFilterKey(CONTEXT, USER, statusFilter(WORKFLOW_INSTANCE_STATUS_FILTER, operator, values));
        const current = await adaptFilterToWorkflowFilterKey(CONTEXT, USER, statusFilter(WORKFLOW_FILTER, operator, values));
        expect(legacy.newFilterGroup).toEqual(current.newFilterGroup);
        expect(legacy.newFilter?.key).toEqual(current.newFilter?.key);
      }
    });

    it('excludes every listed state with not_eq, whatever the filter mode', async () => {
      const { newFilterGroup } = await adaptFilterToWorkflowFilterKey(CONTEXT, USER, legacyFilter(FilterOperator.NotEq, ['template-review', 'template-done'], FilterMode.Or));

      expect(newFilterGroup?.mode).toEqual(FilterMode.And);
      expect(newFilterGroup?.filters.map((f) => f.operator)).toEqual([FilterOperator.NotEq, FilterOperator.NotEq]);
    });

    it('matches any listed state with eq, whatever the filter mode', async () => {
      const { newFilterGroup } = await adaptFilterToWorkflowFilterKey(CONTEXT, USER, legacyFilter(FilterOperator.Eq, ['template-review', 'template-done'], FilterMode.And));

      expect(newFilterGroup?.mode).toEqual(FilterMode.Or);
    });

    it('accepts only_eq_to and not_only_eq_to as eq and not_eq: a draft is in a single state', async () => {
      const onlyEq = await adaptFilterToWorkflowFilterKey(CONTEXT, USER, legacyFilter(FilterOperator.OnlyEqTo, ['template-done']));
      const eq = await adaptFilterToWorkflowFilterKey(CONTEXT, USER, legacyFilter(FilterOperator.Eq, ['template-done']));
      const notOnlyEq = await adaptFilterToWorkflowFilterKey(CONTEXT, USER, legacyFilter(FilterOperator.NotOnlyEqTo, ['template-done']));
      const notEq = await adaptFilterToWorkflowFilterKey(CONTEXT, USER, legacyFilter(FilterOperator.NotEq, ['template-done']));

      expect(onlyEq.newFilterGroup).toEqual(eq.newFilterGroup);
      expect(notOnlyEq.newFilterGroup).toEqual(notEq.newFilterGroup);
    });
  });
});
