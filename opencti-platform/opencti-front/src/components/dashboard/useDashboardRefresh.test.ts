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
      vi.advanceTimersByTime(5_000);
    });

    expect(result.current.refreshToken).toBe(2);
    expect(result.current.isAutoRefreshing).toBe(true);
  });
});
