import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { InterruptibleTimer } from '../../../src/manager/interruptible-timer';

describe('InterruptibleTimer', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('should resolve after the specified timeout duration', async () => {
    const timer = new InterruptibleTimer();
    let resolved = false;

    const promise = timer.start(1000).then(() => { resolved = true; });

    expect(resolved).toBe(false);
    vi.advanceTimersByTime(999);
    await Promise.resolve(); // flush microtasks
    expect(resolved).toBe(false);

    vi.advanceTimersByTime(1);
    await promise;
    expect(resolved).toBe(true);
  });

  it('should resolve immediately when interrupted before timeout', async () => {
    const timer = new InterruptibleTimer();
    let resolved = false;

    const promise = timer.start(10000).then(() => { resolved = true; });

    expect(resolved).toBe(false);
    timer.interrupt();

    await promise;
    expect(resolved).toBe(true);
  });

  it('should not advance time when interrupted early', async () => {
    const timer = new InterruptibleTimer();
    const startTime = Date.now();

    const promise = timer.start(5000);
    timer.interrupt();
    await promise;

    // Time should not have advanced (no real timers ran)
    expect(Date.now() - startTime).toBeLessThan(5000);
  });

  it('should work for multiple sequential starts', async () => {
    const timer = new InterruptibleTimer();

    const promise1 = timer.start(1000);
    vi.advanceTimersByTime(1000);
    await promise1;

    const promise2 = timer.start(2000);
    vi.advanceTimersByTime(2000);
    await promise2;
    // Both promises resolved sequentially without error
  });

  it('should cancel the previous timer when start is called again', async () => {
    const timer = new InterruptibleTimer();
    const clearTimeoutSpy = vi.spyOn(global, 'clearTimeout');

    // Start a timer, then start another before the first one finishes.
    // The first timeout should be cleared and the second should resolve normally.
    timer.start(5000); // intentionally not awaited — its resolve is replaced
    const promise2 = timer.start(500);

    expect(clearTimeoutSpy).toHaveBeenCalled();

    vi.advanceTimersByTime(500);
    await promise2;

    clearTimeoutSpy.mockRestore();
  });

  it('should not throw when interrupt is called on an idle timer', () => {
    const timer = new InterruptibleTimer();
    expect(() => timer.interrupt()).not.toThrow();
  });

  it('should not throw when interrupt is called after the timer has already resolved', async () => {
    const timer = new InterruptibleTimer();

    const promise = timer.start(1000);
    vi.advanceTimersByTime(1000);
    await promise;

    expect(() => timer.interrupt()).not.toThrow();
  });

  it('should allow reuse after interrupt', async () => {
    const timer = new InterruptibleTimer();

    const promise1 = timer.start(5000);
    timer.interrupt();
    await promise1;

    // Timer should be reusable after interrupt
    const promise2 = timer.start(1000);
    vi.advanceTimersByTime(1000);
    await promise2;
  });

  it('should clear state after natural timeout resolution', async () => {
    const timer = new InterruptibleTimer();

    const promise = timer.start(1000);
    vi.advanceTimersByTime(1000);
    await promise;

    // Internal state should be cleared; interrupt should be a no-op
    expect(() => timer.interrupt()).not.toThrow();
  });
});
