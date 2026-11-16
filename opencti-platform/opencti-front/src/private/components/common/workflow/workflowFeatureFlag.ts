// The extended workflow engine/UI is always enabled for DraftWorkspace. For every other entity
// type, it is gated behind the ENTITIES_WORKFLOW feature flag until the rollout is complete.
export const ENTITIES_WORKFLOW_FEATURE_FLAG = 'ENTITIES_WORKFLOW';

export const isWorkflowUiEnabledForType = (
  entityType: string,
  isFeatureEnable: (id: string) => boolean,
): boolean => entityType === 'DraftWorkspace' || isFeatureEnable(ENTITIES_WORKFLOW_FEATURE_FLAG);

// The closing reason is stored in x_opencti_closing_reason, which only domain objects carry.
export const isClosingReasonEnabledForType = (
  entityType: string,
  isFeatureEnable: (id: string) => boolean,
  sdoTypes: ReadonlyArray<{ id: string }> = [],
): boolean => isFeatureEnable(ENTITIES_WORKFLOW_FEATURE_FLAG) && sdoTypes.some((sdo) => sdo.id === entityType);
