import { act, renderHook } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import useIntervalBoostable from './useIntervalBoostable';

const options = {
  baseFrequency: 15000,
  boostFrequency: 3000,
  boostDuration: 10000,
};

/**
 * Advances the fake clock inside act so React applies the resulting state updates.
 */
const advance = (ms: number) => {
  act(() => {
    vi.advanceTimersByTime(ms);
  });
};

describe('Hook: useIntervalBoostable', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('calls the callback on mount then at the default base frequency', () => {
    const callback = vi.fn();
    renderHook(() => useIntervalBoostable(callback));

    expect(callback).toHaveBeenCalledTimes(1);

    advance(19999);
    expect(callback).toHaveBeenCalledTimes(1);

    advance(1);
    expect(callback).toHaveBeenCalledTimes(2);
  });

  it('calls the callback at the default boost frequency once boosted', () => {
    const callback = vi.fn();
    const { result } = renderHook(() => useIntervalBoostable(callback));

    act(() => {
      result.current.activateBoost();
    });

    // Changing the frequency restarts the interval, which calls the callback right away
    expect(callback).toHaveBeenCalledTimes(2);

    advance(5000);
    expect(callback).toHaveBeenCalledTimes(3);
  });

  it('calls the callback at the given base frequency', () => {
    const callback = vi.fn();
    renderHook(() => useIntervalBoostable(callback, options));

    advance(14999);
    expect(callback).toHaveBeenCalledTimes(1);

    advance(1);
    expect(callback).toHaveBeenCalledTimes(2);

    advance(15000);
    expect(callback).toHaveBeenCalledTimes(3);
  });

  it('calls the callback at the boost frequency during the boost duration', () => {
    const callback = vi.fn();
    const { result } = renderHook(() => useIntervalBoostable(callback, options));

    act(() => {
      result.current.activateBoost();
    });
    expect(callback).toHaveBeenCalledTimes(2);

    advance(3000);
    expect(callback).toHaveBeenCalledTimes(3);

    advance(6000);
    expect(callback).toHaveBeenCalledTimes(5);
  });

  it('goes back to the base frequency once the boost duration is over', () => {
    const callback = vi.fn();
    const { result } = renderHook(() => useIntervalBoostable(callback, options));

    act(() => {
      result.current.activateBoost();
    });

    // 3 boosted calls, then the frequency reset calls the callback right away
    advance(10000);
    expect(callback).toHaveBeenCalledTimes(6);

    advance(14999);
    expect(callback).toHaveBeenCalledTimes(6);

    advance(1);
    expect(callback).toHaveBeenCalledTimes(7);
  });

  it('extends the boost when activated again while boosted', () => {
    const callback = vi.fn();
    const { result } = renderHook(() => useIntervalBoostable(callback, options));

    act(() => {
      result.current.activateBoost();
    });
    advance(6000);
    expect(callback).toHaveBeenCalledTimes(4);

    // Already boosted: the frequency does not change, so no immediate call
    act(() => {
      result.current.activateBoost();
    });
    expect(callback).toHaveBeenCalledTimes(4);

    // Still boosted after the first boost would have ended
    advance(9000);
    expect(callback).toHaveBeenCalledTimes(7);

    // The second boost ends 10s after it was activated
    advance(1000);
    expect(callback).toHaveBeenCalledTimes(8);

    advance(15000);
    expect(callback).toHaveBeenCalledTimes(9);
  });

  it('calls the latest callback after a rerender', () => {
    const firstCallback = vi.fn();
    const secondCallback = vi.fn();
    const { rerender } = renderHook(
      ({ callback }) => useIntervalBoostable(callback, options),
      { initialProps: { callback: firstCallback } },
    );

    rerender({ callback: secondCallback });
    advance(15000);

    expect(firstCallback).toHaveBeenCalledTimes(1);
    expect(secondCallback).toHaveBeenCalledTimes(1);
  });

  it('stops calling the callback once unmounted', () => {
    const callback = vi.fn();
    const { result, unmount } = renderHook(() => useIntervalBoostable(callback, options));

    act(() => {
      result.current.activateBoost();
    });
    unmount();
    advance(60000);

    expect(callback).toHaveBeenCalledTimes(2);
  });

  it('clears the pending boost end on unmount', () => {
    const { result, unmount } = renderHook(() => useIntervalBoostable(vi.fn(), options));

    act(() => {
      result.current.activateBoost();
    });
    expect(vi.getTimerCount()).toBe(2);

    unmount();
    expect(vi.getTimerCount()).toBe(0);
  });
});
