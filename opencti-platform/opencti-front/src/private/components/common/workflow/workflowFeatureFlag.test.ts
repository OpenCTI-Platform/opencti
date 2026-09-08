import { describe, it, expect, vi } from 'vitest';
import { ENTITIES_WORKFLOW_FEATURE_FLAG, isWorkflowUiEnabledForType } from './workflowFeatureFlag';

describe('isWorkflowUiEnabledForType', () => {
  it('should always return true for DraftWorkspace regardless of the feature flag', () => {
    const isFeatureEnable = vi.fn().mockReturnValue(false);
    expect(isWorkflowUiEnabledForType('DraftWorkspace', isFeatureEnable)).toBe(true);
    expect(isFeatureEnable).not.toHaveBeenCalled();
  });

  it('should return false for other entity types when the feature flag is disabled', () => {
    const isFeatureEnable = vi.fn().mockReturnValue(false);
    expect(isWorkflowUiEnabledForType('Incident', isFeatureEnable)).toBe(false);
    expect(isFeatureEnable).toHaveBeenCalledWith(ENTITIES_WORKFLOW_FEATURE_FLAG);
  });

  it('should return true for other entity types when the feature flag is enabled', () => {
    const isFeatureEnable = vi.fn().mockReturnValue(true);
    expect(isWorkflowUiEnabledForType('Incident', isFeatureEnable)).toBe(true);
    expect(isFeatureEnable).toHaveBeenCalledWith(ENTITIES_WORKFLOW_FEATURE_FLAG);
  });
});
