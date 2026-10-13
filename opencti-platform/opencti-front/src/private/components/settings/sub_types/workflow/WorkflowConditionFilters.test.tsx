import { describe, it, expect } from 'vitest';
import { getWorkflowConditionFilterKeys, WORKFLOW_CONTEXT_FILTER_KEYS } from './WorkflowConditionFilters';

// subset of the stix filtering keys, as returned by useStixFilters
const stixFilters = ['entity_type', 'workflow_id', 'objectLabel', 'createdBy', 'name'];

describe('getWorkflowConditionFilterKeys', () => {
  it('keeps the workflow context keys when the entity type has no filter keys', () => {
    expect(getWorkflowConditionFilterKeys([], stixFilters)).toEqual(WORKFLOW_CONTEXT_FILTER_KEYS);
  });

  it('adds the entity filter keys supported by stix filtering', () => {
    const keys = getWorkflowConditionFilterKeys(['objectLabel', 'workflow_id', 'createdBy'], stixFilters);
    expect(keys).toEqual([...WORKFLOW_CONTEXT_FILTER_KEYS, 'objectLabel', 'workflow_id', 'createdBy']);
  });

  it('drops entity filter keys that stix filtering cannot evaluate', () => {
    const keys = getWorkflowConditionFilterKeys(['created_at', 'objectLabel', 'regardingOf'], stixFilters);
    expect(keys).not.toContain('created_at');
    expect(keys).not.toContain('regardingOf');
    expect(keys).toContain('objectLabel');
  });

  it('drops the entity_type key, always equal to the workflow entity type', () => {
    expect(getWorkflowConditionFilterKeys(['entity_type', 'objectLabel'], stixFilters)).not.toContain('entity_type');
  });

  it('does not duplicate a key present in both lists', () => {
    const keys = getWorkflowConditionFilterKeys(['name', 'objectLabel'], stixFilters);
    expect(keys.filter((k) => k === 'name')).toHaveLength(1);
  });
});
