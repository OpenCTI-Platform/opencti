import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { InterruptibleTimer } from '../../../src/manager/interruptible-timer';

describe('interruptible time test coverage', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('should start resolve after the specified duration', async () => {
    const timer = new InterruptibleTimer();

    let resolved = false;
    const promise = timer.start(60_000).then(() => {
      resolved = true;
    });

    expect(resolved).toBe(false);

    await vi.advanceTimersByTimeAsync(60_000);
    await promise;

    expect(resolved).toBe(true);
  });

  it('should interruption before the end of timer works', async () => {
    const timer = new InterruptibleTimer();

    let resolved = false;
    const promise = timer.start(60_000).then(() => {
      resolved = true;
    });

    expect(resolved).toBe(false);

    // Advance only 500ms then interrupt — should resolve without waiting the full 60s
    await vi.advanceTimersByTimeAsync(500);
    timer.interrupt();
    await promise;

    expect(resolved).toBe(true);
  });
});
