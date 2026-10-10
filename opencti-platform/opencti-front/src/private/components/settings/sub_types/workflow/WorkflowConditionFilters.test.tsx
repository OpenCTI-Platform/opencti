import { describe, it, expect } from 'vitest';
import { getWorkflowConditionFilterKeys, WORKFLOW_CONTEXT_FILTER_KEYS } from './WorkflowConditionFilters';

describe('getWorkflowConditionFilterKeys', () => {
  it('keeps the workflow context keys when the entity type has no filter keys', () => {
    expect(getWorkflowConditionFilterKeys([])).toEqual(WORKFLOW_CONTEXT_FILTER_KEYS);
  });

  it('adds the entity filter keys supported by stix filtering', () => {
    const keys = getWorkflowConditionFilterKeys(['objectLabel', 'workflow_id', 'createdBy']);
    expect(keys).toEqual([...WORKFLOW_CONTEXT_FILTER_KEYS, 'objectLabel', 'workflow_id', 'createdBy']);
  });

  it('drops entity filter keys that stix filtering cannot evaluate', () => {
    const keys = getWorkflowConditionFilterKeys(['created_at', 'objectLabel', 'regardingOf']);
    expect(keys).not.toContain('created_at');
    expect(keys).not.toContain('regardingOf');
    expect(keys).toContain('objectLabel');
  });

  it('drops the entity_type key, always equal to the workflow entity type', () => {
    expect(getWorkflowConditionFilterKeys(['entity_type', 'objectLabel'])).not.toContain('entity_type');
  });

  it('does not duplicate a key present in both lists', () => {
    const keys = getWorkflowConditionFilterKeys(['name', 'objectLabel']);
    expect(keys.filter((k) => k === 'name')).toHaveLength(1);
  });
});
