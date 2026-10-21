import { describe, expect, it } from 'vitest';
import { buildTransitionOptions, buildWorkflowStatusOptions, buildWorkflowTransitionAction, isFieldOptionDisabled, withWorkflowBypassOptions } from './workflowMassActions';

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

  it('should send a null event name when no event is selected, so the backend rejects the task', () => {
    const action = buildWorkflowTransitionAction({ type: 'REPLACE', fieldType: 'ATTRIBUTE', values: [] });

    expect(action.context.options).toEqual({ eventName: null });
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

    expect(options).toEqual([
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
