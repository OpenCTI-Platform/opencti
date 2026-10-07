import { describe, expect, it } from 'vitest';
import { buildWorkflowTransitionAction } from './workflowMassActions';

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
