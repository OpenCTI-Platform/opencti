import { buildTransitionRuntimeParams, EMPTY_TRANSITION_INPUT_VALUES, hasTransitionComment, TransitionInputRequirements, TransitionInputValues } from './WorkflowTransitionInputs';

export const WORKFLOW_STATUS_FIELD = 'x_opencti_workflow_id';
// Toolbar-only field, sent to the backend as a replace of the workflow status with an event name
export const WORKFLOW_TRANSITION_FIELD = 'x_opencti_workflow_id_transition';

interface TransitionOption {
  label: string;
  value: string;
  requirements?: TransitionInputRequirements;
}

// The comment and organizations collected for a mass transition, and whether they are complete
export type MassTransitionInputs = Partial<TransitionInputValues> & { inputsValid?: boolean };

interface WorkflowActionInput {
  type: string;
  fieldType?: string;
  values: TransitionOption[];
  transitionInputs?: MassTransitionInputs;
}

// The inputs live beside the row options, which are sent to the backend as they are whatever the row's field becomes
export const setTransitionInputs = <T extends object>(row: T, inputs: MassTransitionInputs) => ({ ...row, transitionInputs: inputs });

interface MassTransition {
  event: string;
  toState: string;
  toStatus?: { template?: { name: string } | null } | null;
  comment?: string | null;
  requiresShareOrganizationInput?: boolean | null;
  requiresUnshareOrganizationInput?: boolean | null;
}

export const buildTransitionOptions = (transitions: readonly MassTransition[]): TransitionOption[] => transitions.map((transition) => ({
  label: `${transition.event} → ${transition.toStatus?.template?.name ?? transition.toState}`,
  value: transition.event,
  requirements: {
    commentMode: transition.comment,
    requiresShareOrg: !!transition.requiresShareOrganizationInput,
    requiresUnshareOrg: !!transition.requiresUnshareOrganizationInput,
  },
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

const NO_REQUIREMENTS: TransitionInputRequirements = { requiresShareOrg: false, requiresUnshareOrg: false };

export const buildWorkflowTransitionAction = (input: WorkflowActionInput) => {
  const requirements = input.values[0]?.requirements ?? NO_REQUIREMENTS;
  const inputs = { ...EMPTY_TRANSITION_INPUT_VALUES, ...input.transitionInputs };
  const comment = hasTransitionComment(requirements.commentMode) ? inputs.comment.trim() : '';
  return {
    type: input.type,
    context: {
      field: WORKFLOW_STATUS_FIELD,
      type: input.fieldType,
      values: [],
      options: {
        // Never undefined: a dropped key would turn the task into a plain replace that clears the status
        eventName: input.values[0]?.value ?? null,
        ...(comment ? { comment } : {}),
        ...buildTransitionRuntimeParams(requirements, inputs),
      },
    },
  };
};

// A transition step is complete once its comment and organizations are
export const isTransitionInputValid = (input: WorkflowActionInput) => input.transitionInputs?.inputsValid === true;

// With the workflow, a status only changes through a transition, unless the user can bypass the workflow
export const canReplaceStatusDirectly = ({ workflowEnabled, canBypassWorkflow }: { workflowEnabled: boolean; canBypassWorkflow: boolean }) => {
  return !workflowEnabled || canBypassWorkflow;
};

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
