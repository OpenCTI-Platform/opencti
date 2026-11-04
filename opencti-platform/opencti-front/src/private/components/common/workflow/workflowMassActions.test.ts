import { describe, expect, it } from 'vitest';
import {
  buildTransitionOptions,
  buildWorkflowStatusOptions,
  buildWorkflowTransitionAction,
  isFieldOptionDisabled,
  canReplaceStatusDirectly,
  isTransitionInputValid,
  setTransitionInputs,
  withWorkflowBypassOptions,
} from './workflowMassActions';

describe('buildWorkflowTransitionAction', () => {
  it('should send the selected event as a replace of the workflow status', () => {
    const action = buildWorkflowTransitionAction({
      type: 'REPLACE',
      fieldType: 'ATTRIBUTE',
      values: [{ label: 'approve', value: 'approve' }],
    });

    expect(action).toEqual({
      type: 'REPLACE',
      context: {
        field: 'x_opencti_workflow_id',
        type: 'ATTRIBUTE',
        values: [],
        options: { eventName: 'approve' },
      },
    });
  });

  it('should send the comment and the organizations the transition needs', () => {
    const [option] = buildTransitionOptions([
      { event: 'approve', toState: 'approved', comment: 'required', requiresShareOrganizationInput: true, requiresUnshareOrganizationInput: false },
    ]);
    const action = buildWorkflowTransitionAction(setTransitionInputs({ type: 'REPLACE', values: [option] }, {
      comment: '  Checked  ',
      shareOrganizations: [{ value: 'org-1', label: 'Org 1' }],
      unshareOrganizations: [{ value: 'org-2', label: 'Org 2' }],
      inputsValid: true,
    }));

    expect(action.context.options).toEqual({ eventName: 'approve', comment: 'Checked', shareOrganizationIds: ['org-1'] });
  });

  it('should send no comment for a transition without one, even if one was typed for another transition', () => {
    const [option] = buildTransitionOptions([{ event: 'approve', toState: 'approved', comment: 'disabled' }]);
    const action = buildWorkflowTransitionAction(setTransitionInputs({ type: 'REPLACE', values: [option] }, { comment: 'Left over' }));

    expect(action.context.options).toEqual({ eventName: 'approve' });
  });

  it('should send a null event name when no event is selected, so the backend rejects the task', () => {
    const action = buildWorkflowTransitionAction({ type: 'REPLACE', fieldType: 'ATTRIBUTE', values: [] });

    expect(action.context.options).toEqual({ eventName: null });
  });
});

describe('isTransitionInputValid', () => {
  it('should wait for the transition inputs to be reported complete', () => {
    const row = { type: 'REPLACE', values: [] };
    expect(isTransitionInputValid(row)).toBe(false);
    expect(isTransitionInputValid(setTransitionInputs(row, { inputsValid: false }))).toBe(false);
    expect(isTransitionInputValid(setTransitionInputs(row, { inputsValid: true }))).toBe(true);
  });
});

describe('setTransitionInputs', () => {
  it('should keep the transition inputs out of the options sent to the backend, for when the row switches to another field', () => {
    const row = { type: 'REPLACE', field: 'x_opencti_workflow_id', values: [], options: { applyTransitionActions: false } };

    const updated = setTransitionInputs(row, { comment: 'Checked', shareOrganizations: [{ value: 'org-1' }], unshareOrganizations: [], inputsValid: true });

    expect(updated.options).toEqual({ applyTransitionActions: false });
  });
});

describe('canReplaceStatusDirectly', () => {
  it('should offer the direct status change only to bypass users once the workflow is enabled', () => {
    expect(canReplaceStatusDirectly({ workflowEnabled: false, canBypassWorkflow: false })).toBe(true);
    expect(canReplaceStatusDirectly({ workflowEnabled: true, canBypassWorkflow: true })).toBe(true);
    expect(canReplaceStatusDirectly({ workflowEnabled: true, canBypassWorkflow: false })).toBe(false);
  });
});

describe('withWorkflowBypassOptions', () => {
  it('should apply the transition actions by default', () => {
    expect(withWorkflowBypassOptions(undefined)).toEqual({ applyTransitionActions: true });
  });

  it('should keep the choice of the user', () => {
    expect(withWorkflowBypassOptions({ applyTransitionActions: false })).toEqual({ applyTransitionActions: false });
  });
});

describe('buildTransitionOptions', () => {
  it('should label each transition with its target status', () => {
    const options = buildTransitionOptions([
      { event: 'start', toState: 'analyse', toStatus: { template: { name: 'Analyse' } } },
      { event: 'reject', toState: 'rejected', toStatus: null },
    ]);

    expect(options.map(({ label, value }) => ({ label, value }))).toEqual([
      { label: 'start → Analyse', value: 'start' },
      { label: 'reject → rejected', value: 'reject' },
    ]);
  });
});

describe('isFieldOptionDisabled', () => {
  it('should let a row swap between Status and Workflow transition', () => {
    const actionsInputs = [{ type: 'REPLACE', field: 'x_opencti_workflow_id' }];
    expect(isFieldOptionDisabled(actionsInputs, 0, 'x_opencti_workflow_id_transition')).toBe(false);
  });

  it('should disable Workflow transition when another row replaces the Status', () => {
    const actionsInputs = [{ type: 'REPLACE', field: 'x_opencti_workflow_id' }, { type: 'REPLACE' }];
    expect(isFieldOptionDisabled(actionsInputs, 1, 'x_opencti_workflow_id_transition')).toBe(true);
  });

  it('should disable a field replaced in another row', () => {
    const actionsInputs = [{ type: 'REPLACE', field: 'description' }, { type: 'ADD' }];
    expect(isFieldOptionDisabled(actionsInputs, 1, 'description')).toBe(true);
    expect(isFieldOptionDisabled(actionsInputs, 1, 'object-label')).toBe(false);
  });
});

describe('buildWorkflowStatusOptions', () => {
  it('should keep the workflow order and the status to display', () => {
    const status = { id: 'status-new', order: 0, template: { name: 'New', color: '#ff0000' } };

    expect(buildWorkflowStatusOptions([status])).toEqual([{ label: 'New', value: 'status-new', status }]);
  });
});
