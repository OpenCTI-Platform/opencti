import { describe, it, expect, vi } from 'vitest';
import { ENTITIES_WORKFLOW_FEATURE_FLAG, isClosingReasonEnabledForType, isWorkflowUiEnabledForType } from './workflowFeatureFlag';

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

describe('isClosingReasonEnabledForType', () => {
  const sdoTypes = [{ id: 'Case-Incident' }];

  it('should return true for a domain object type when the feature flag is enabled', () => {
    expect(isClosingReasonEnabledForType('Case-Incident', () => true, sdoTypes)).toBe(true);
  });

  it('should return false when the feature flag is disabled', () => {
    expect(isClosingReasonEnabledForType('Case-Incident', () => false, sdoTypes)).toBe(false);
  });

  it('should return false for types that are not domain objects', () => {
    expect(isClosingReasonEnabledForType('DraftWorkspace', () => true, sdoTypes)).toBe(false);
    expect(isClosingReasonEnabledForType('stix-sighting-relationship', () => true, sdoTypes)).toBe(false);
  });
});
