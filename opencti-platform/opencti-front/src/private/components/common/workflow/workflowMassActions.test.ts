import { describe, expect, it } from 'vitest';
import { buildTransitionOptions, buildWorkflowTransitionAction, withWorkflowBypassOptions } from './workflowMassActions';

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
