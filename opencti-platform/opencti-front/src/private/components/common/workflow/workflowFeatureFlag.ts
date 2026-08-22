export const ENTITIES_WORKFLOW_FEATURE_FLAG = 'ENTITIES_WORKFLOW';

/**
 * The extended workflow UI (workflow status display, transition actions, definition editor
 * actions) is gated behind the `ENTITIES_WORKFLOW` feature flag for every entity type other than
 * `DraftWorkspace`, which has always used the workflow engine/UI and must keep behaving exactly
 * as before this change regardless of the flag (plan.md Task 5, Step 1/2; spec.md "Feature-flagged
 * rollout").
 */
export const isWorkflowUiEnabledForType = (
  entityType: string,
  isFeatureEnable: (id: string) => boolean,
): boolean => entityType === 'DraftWorkspace' || isFeatureEnable(ENTITIES_WORKFLOW_FEATURE_FLAG);
