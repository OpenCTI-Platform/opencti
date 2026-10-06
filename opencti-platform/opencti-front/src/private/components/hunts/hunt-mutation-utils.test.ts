import { afterEach, describe, expect, it, vi } from 'vitest';
import { MESSAGING$ } from '../../../relay/environment';
import { notifyPayloadErrors } from './hunt-mutation-utils';

describe('notifyPayloadErrors', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('lets the success path run without payload errors', () => {
    const notifyError = vi.spyOn(MESSAGING$, 'notifyError').mockImplementation(() => {});
    expect(notifyPayloadErrors(null)).toBe(false);
    expect(notifyPayloadErrors(undefined)).toBe(false);
    expect(notifyPayloadErrors([])).toBe(false);
    expect(notifyError).not.toHaveBeenCalled();
  });

  it('notifies every payload error and stops the success path', () => {
    const notifyError = vi.spyOn(MESSAGING$, 'notifyError').mockImplementation(() => {});
    expect(notifyPayloadErrors([{ message: 'Hunt not found' }, { message: 'Forbidden' }])).toBe(true);
    expect(notifyError).toHaveBeenNthCalledWith(1, 'Hunt not found');
    expect(notifyError).toHaveBeenNthCalledWith(2, 'Forbidden');
  });
});
