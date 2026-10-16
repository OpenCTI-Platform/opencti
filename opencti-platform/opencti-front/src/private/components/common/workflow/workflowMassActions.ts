export const WORKFLOW_STATUS_FIELD = 'x_opencti_workflow_id';
// Toolbar-only field, sent to the backend as a replace of the workflow status with an event name
export const WORKFLOW_TRANSITION_FIELD = 'x_opencti_workflow_id_transition';

interface WorkflowActionInput {
  type: string;
  fieldType?: string;
  values: { label: string; value: string }[];
}

interface MassTransition {
  event: string;
  toState: string;
  toStatus?: { template?: { name: string } | null } | null;
}

export const buildTransitionOptions = (transitions: readonly MassTransition[]) => transitions.map((transition) => ({
  label: `${transition.event} → ${transition.toStatus?.template?.name ?? transition.toState}`,
  value: transition.event,
}));

interface WorkflowStatus {
  id: string;
  order: number;
  template?: { name: string; color: string } | null;
}

export const buildWorkflowStatusOptions = <T extends WorkflowStatus>(statuses: readonly T[]) => statuses.map((status) => ({
  label: status.template?.name ?? status.id,
  value: status.id,
  status,
}));

export const buildWorkflowTransitionAction = (input: WorkflowActionInput) => ({
  type: input.type,
  context: {
    field: WORKFLOW_STATUS_FIELD,
    type: input.fieldType,
    values: [],
    options: { eventName: input.values[0]?.value },
  },
});

// For a bypass user, a status update goes through the workflow engine, with the transition actions by default
export const withWorkflowBypassOptions = (options?: { applyTransitionActions?: boolean }) => ({
  ...options,
  applyTransitionActions: options?.applyTransitionActions ?? true,
});

interface ActionInput {
  type?: string;
  field?: string;
}

const toBackendField = (field?: string) => (field === WORKFLOW_TRANSITION_FIELD ? WORKFLOW_STATUS_FIELD : field);

// A field cannot get several actions when one of them is a replace. Status and Workflow transition
// write the same field, so they exclude each other across rows, but a row can swap between them.
export const isFieldOptionDisabled = (actionsInputs: ActionInput[], index: number, field: string) => {
  const backendField = toBackendField(field);
  if (toBackendField(actionsInputs[index]?.field) === backendField) return false;
  const otherInputs = actionsInputs.filter((_, inputIndex) => inputIndex !== index);
  const isReplacedElsewhere = otherInputs.some((input) => input.type === 'REPLACE' && toBackendField(input.field) === backendField);
  const isUsedElsewhere = otherInputs.some((input) => toBackendField(input.field) === backendField);
  return isReplacedElsewhere || (isUsedElsewhere && actionsInputs[index]?.type === 'REPLACE');
};
