export const WORKFLOW_STATUS_FIELD = 'x_opencti_workflow_id';
// Toolbar-only field, sent to the backend as a replace of the workflow status with an event name
export const WORKFLOW_TRANSITION_FIELD = 'x_opencti_workflow_id_transition';

interface WorkflowActionInput {
  type: string;
  fieldType?: string;
  values: { label: string; value: string }[];
}

export const buildWorkflowTransitionAction = (input: WorkflowActionInput) => ({
  type: input.type,
  context: {
    field: WORKFLOW_STATUS_FIELD,
    type: input.fieldType,
    values: [],
    options: { eventName: input.values[0]?.value },
  },
});
