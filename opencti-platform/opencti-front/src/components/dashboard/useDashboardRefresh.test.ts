import { act, renderHook } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import useDashboardRefresh from './useDashboardRefresh';

describe('useDashboardRefresh', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-06-05T12:00:00.000Z'));
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('initializes with a disabled refresh rate by default', () => {
    const { result } = renderHook(() => useDashboardRefresh({}));

    expect(result.current.localRefreshRateSeconds).toBe(0);
    expect(result.current.refreshRate).toBeNull();
    expect(result.current.refreshToken).toBe(0);
    expect(result.current.isAutoRefreshing).toBe(false);
  });

  it('increments refresh token on manual refresh', () => {
    const { result } = renderHook(() => useDashboardRefresh({}));

    act(() => {
      result.current.handleManualRefresh();
    });

    expect(result.current.refreshToken).toBe(1);
    expect(result.current.isAutoRefreshing).toBe(false);
  });

  it('updates local refresh rate and notifies callback when interval changes', () => {
    const onRefreshRateChange = vi.fn();
    const { result } = renderHook(() => useDashboardRefresh({
      initialRefreshRateSeconds: 10,
      onRefreshRateChange,
    }));

    act(() => {
      result.current.handleRefreshRateChange(15);
    });

    expect(result.current.localRefreshRateSeconds).toBe(15);
    expect(result.current.refreshRate).toBe(15_000);
    expect(onRefreshRateChange).toHaveBeenCalledWith(15);
  });

  it('resets the countdown without refetching when the refresh rate changes', () => {
    const { result } = renderHook(() => useDashboardRefresh({
      initialRefreshRateSeconds: 10,
    }));

    // Wait almost a full interval on the original rate.
    act(() => {
      vi.advanceTimersByTime(9_000);
    });
    expect(result.current.refreshToken).toBe(0);

    // Changing the rate must not trigger an immediate refresh.
    act(() => {
      result.current.handleRefreshRateChange(20);
    });
    expect(result.current.refreshToken).toBe(0);

    // The elapsed 9s must be discarded: no tick until a full new interval passes.
    act(() => {
      vi.advanceTimersByTime(19_999);
    });
    expect(result.current.refreshToken).toBe(0);

    act(() => {
      vi.advanceTimersByTime(1);
    });
    expect(result.current.refreshToken).toBe(1);
  });

  it('synchronizes local refresh rate when initial refresh rate changes', () => {
    const { result, rerender } = renderHook(
      ({ initialRefreshRateSeconds }) => useDashboardRefresh({ initialRefreshRateSeconds }),
      {
        initialProps: { initialRefreshRateSeconds: 10 },
      },
    );

    expect(result.current.localRefreshRateSeconds).toBe(10);
    expect(result.current.refreshRate).toBe(10_000);

    rerender({ initialRefreshRateSeconds: 60 });

    expect(result.current.localRefreshRateSeconds).toBe(60);
    expect(result.current.refreshRate).toBe(60_000);
  });

  it('auto-refreshes on interval and toggles spinner state', () => {
    const { result } = renderHook(() => useDashboardRefresh({
      initialRefreshRateSeconds: 5,
    }));

    expect(result.current.refreshToken).toBe(0);
    expect(result.current.isAutoRefreshing).toBe(false);

    act(() => {
      vi.advanceTimersByTime(4_999);
    });

    expect(result.current.refreshToken).toBe(0);
    expect(result.current.isAutoRefreshing).toBe(false);

    act(() => {
      vi.advanceTimersByTime(1);
    });

    expect(result.current.refreshToken).toBe(1);
    expect(result.current.isAutoRefreshing).toBe(true);

    act(() => {
      vi.advanceTimersByTime(1_200);
    });

    expect(result.current.isAutoRefreshing).toBe(false);

    act(() => {
      // Next interval tick is 3.8s after the spinner reset (t=6.2s -> t=10s).
      vi.advanceTimersByTime(3_800);
    });

    expect(result.current.refreshToken).toBe(2);
    expect(result.current.isAutoRefreshing).toBe(true);

    act(() => {
      vi.advanceTimersByTime(1_200);
    });

    expect(result.current.isAutoRefreshing).toBe(false);
  });
});
