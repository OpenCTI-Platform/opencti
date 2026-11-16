import { afterEach, describe, expect, it, vi } from 'vitest';
import { waitDrained } from '../../../src/intake/workerless/push-consumer';

describe('push consumer drain on close (task 0040)', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('should return at once when nothing is in flight', async () => {
    expect(await waitDrained(() => 0, 60000, 100)).toBe(true);
  });

  it('should wait until the messages in flight are answered', async () => {
    vi.useFakeTimers();
    let pending = 2;
    let settled = false;
    const drained = waitDrained(() => pending, 60000, 100).then((value) => {
      settled = true;
      return value;
    });
    await vi.advanceTimersByTimeAsync(500);
    expect(settled).toBe(false);
    pending = 0;
    await vi.advanceTimersByTimeAsync(100);
    expect(await drained).toBe(true);
  });

  it('should give up at the bound with messages still in flight', async () => {
    vi.useFakeTimers();
    let settled = false;
    const drained = waitDrained(() => 1, 60000, 100).then((value) => {
      settled = true;
      return value;
    });
    await vi.advanceTimersByTimeAsync(59000);
    expect(settled).toBe(false);
    await vi.advanceTimersByTimeAsync(1100);
    expect(await drained).toBe(false);
  });
});
