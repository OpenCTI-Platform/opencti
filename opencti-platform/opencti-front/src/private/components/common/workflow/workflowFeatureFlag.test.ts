import { describe, expect, it, vi } from 'vitest';
import { ENTITIES_WORKFLOW_FEATURE_FLAG, isWorkflowUiEnabledForType } from './workflowFeatureFlag';

describe('isWorkflowUiEnabledForType', () => {
  it('is always enabled for DraftWorkspace regardless of the flag', () => {
    expect(isWorkflowUiEnabledForType('DraftWorkspace', () => false)).toBe(true);
    expect(isWorkflowUiEnabledForType('DraftWorkspace', () => true)).toBe(true);
  });

  it('is disabled for other entity types when the flag is off', () => {
    expect(isWorkflowUiEnabledForType('Incident', () => false)).toBe(false);
    expect(isWorkflowUiEnabledForType('Report', () => false)).toBe(false);
  });

  it('is enabled for other entity types when the flag is on', () => {
    const isFeatureEnable = vi.fn((id: string) => id === ENTITIES_WORKFLOW_FEATURE_FLAG);
    expect(isWorkflowUiEnabledForType('Incident', isFeatureEnable)).toBe(true);
    expect(isFeatureEnable).toHaveBeenCalledWith(ENTITIES_WORKFLOW_FEATURE_FLAG);
  });
});
