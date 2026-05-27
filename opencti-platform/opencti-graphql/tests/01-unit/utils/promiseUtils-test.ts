import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { callWithTimeout, TimeoutError } from '../../../src/utils/promiseUtils';

describe('Promise utilities: callWithTimeout', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('should resolve when the wrapped promise settles before timeout', async () => {
    const wrappedPromise = new Promise<string>((resolve) => {
      setTimeout(() => resolve('ok'), 50);
    });

    const promise = callWithTimeout(wrappedPromise, 500);

    await vi.advanceTimersByTimeAsync(50);

    await expect(promise).resolves.toBe('ok');
  });

  it('should reject with TimeoutError when timeout is reached first', async () => {
    const neverResolvingPromise = new Promise<string>(() => {});
    const promise = callWithTimeout(neverResolvingPromise, 100);
    const promiseInstanceOfAssertion = expect(promise).rejects.toBeInstanceOf(TimeoutError);
    const promiseMessageAssertion = expect(promise).rejects.toMatchObject({ message: 'Operation timed out.' });
    await vi.advanceTimersByTimeAsync(100);
    await promiseInstanceOfAssertion;
    await promiseMessageAssertion;
  });

  it('should propagate wrapped promise rejection when it rejects before timeout', async () => {
    const wrappedError = new Error('wrapped failure');
    const wrappedPromise = new Promise<string>((_resolve, reject) => {
      setTimeout(() => reject(wrappedError), 25);
    });
    const promise = callWithTimeout(wrappedPromise, 500);
    const promiseAssertion = expect(promise).rejects.toBe(wrappedError);
    await vi.advanceTimersByTimeAsync(25);
    await promiseAssertion;
  });
});
