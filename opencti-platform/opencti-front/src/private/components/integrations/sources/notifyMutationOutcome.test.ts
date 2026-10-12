import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { PayloadError } from 'relay-runtime';

const { notifyError, notifySuccess } = vi.hoisted(() => ({ notifyError: vi.fn(), notifySuccess: vi.fn() }));
vi.mock('../../../../relay/environment', () => ({ MESSAGING$: { notifyError, notifySuccess } }));

import notifyMutationOutcome from './notifyMutationOutcome';

describe('notifyMutationOutcome', () => {
  beforeEach(() => {
    notifyError.mockReset();
    notifySuccess.mockReset();
  });

  it('reports the payload errors and never the success', () => {
    const errors = [{ message: 'Forbidden' }, { message: 'Invalid input' }] as PayloadError[];
    expect(notifyMutationOutcome(errors, { success: 'Saved' })).toBe(false);
    expect(notifyError).toHaveBeenCalledWith('Forbidden - Invalid input');
    expect(notifySuccess).not.toHaveBeenCalled();
  });

  it('reports a failure resolved without payload errors', () => {
    expect(notifyMutationOutcome(null, { success: 'Applied', failure: 'Not applied' })).toBe(false);
    expect(notifyError).toHaveBeenCalledWith('Not applied');
    expect(notifySuccess).not.toHaveBeenCalled();
  });

  it('reports the success when there is no error', () => {
    expect(notifyMutationOutcome([], { success: 'Saved' })).toBe(true);
    expect(notifySuccess).toHaveBeenCalledWith('Saved');
    expect(notifyError).not.toHaveBeenCalled();
  });

  it('stays silent on success without a message', () => {
    expect(notifyMutationOutcome(undefined)).toBe(true);
    expect(notifySuccess).not.toHaveBeenCalled();
    expect(notifyError).not.toHaveBeenCalled();
  });
});
