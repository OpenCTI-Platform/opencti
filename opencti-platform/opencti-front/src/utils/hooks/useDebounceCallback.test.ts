import { act, renderHook } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import useDebounceCallback from './useDebounceCallback';

describe('Hook: useDebounceCallback', () => {
  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('debounces calls and only executes with the latest arguments', () => {
    vi.useFakeTimers();
    const callback = vi.fn<(value: string) => void>();

    const { result } = renderHook(() => useDebounceCallback(callback, 100));

    act(() => {
      result.current('first');
      result.current('second');
      vi.advanceTimersByTime(99);
    });

    expect(callback).not.toHaveBeenCalled();

    act(() => {
      vi.advanceTimersByTime(1);
    });

    expect(callback).toHaveBeenCalledOnce();
    expect(callback).toHaveBeenCalledWith('second');
  });

  it('exposes cancel to prevent pending execution', () => {
    vi.useFakeTimers();
    const callback = vi.fn<(value: string) => void>();

    const { result } = renderHook(() => useDebounceCallback(callback, 100));

    act(() => {
      result.current('value');
      result.current.cancel();
      vi.advanceTimersByTime(100);
    });

    expect(callback).not.toHaveBeenCalled();
  });

  it('cancels pending timeout on unmount', () => {
    vi.useFakeTimers();
    const callback = vi.fn<() => void>();

    const { result, unmount } = renderHook(() => useDebounceCallback(callback, 100));

    act(() => {
      result.current();
      unmount();
      vi.advanceTimersByTime(100);
    });

    expect(callback).not.toHaveBeenCalled();
  });

  it('supports callbacks with multiple arguments', () => {
    vi.useFakeTimers();
    const callback = vi.fn<(a: string, b: number) => void>();

    const { result } = renderHook(() => useDebounceCallback(callback, 100));

    act(() => {
      result.current('alpha', 42);
      vi.advanceTimersByTime(100);
    });

    expect(callback).toHaveBeenCalledOnce();
    expect(callback).toHaveBeenCalledWith('alpha', 42);
  });
});
