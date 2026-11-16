import { describe, expect, it } from 'vitest';
import { withShareOnlyWhenApproved } from './useWorkflowForm';
import type { WorkflowEditionFormValues } from '../WorkflowEditionDrawer';
import { WorkflowActionType } from '../utils';

const share = { type: WorkflowActionType.shareRequestedEntities, params: { organizations: ['org-1'] } };
const other = { type: WorkflowActionType.updateAuthorizedMembers, params: {} };

describe('withShareOnlyWhenApproved', () => {
  it('moves the share action last on the Approved state, also for an order saved earlier', () => {
    const values = { requestAccessOutcome: 'APPROVED', onEnter: [share, other] } as unknown as WorkflowEditionFormValues;

    expect(withShareOnlyWhenApproved(values).onEnter).toEqual([other, share]);
  });

  it('leaves an Approved state without onEnter actions unchanged', () => {
    const values = { requestAccessOutcome: 'APPROVED' } as unknown as WorkflowEditionFormValues;

    expect(withShareOnlyWhenApproved(values)).toBe(values);
  });

  it('drops the share action from a state that is not Approved', () => {
    const values = { requestAccessOutcome: 'DECLINED', onEnter: [share, other] } as unknown as WorkflowEditionFormValues;

    expect(withShareOnlyWhenApproved(values).onEnter).toEqual([other]);
  });
});
