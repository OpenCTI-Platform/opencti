import { act, renderHook } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import useProvenanceCountsFetchKey, { PROVENANCE_COUNTS_REFRESH_INTERVAL_MS, refreshProvenanceCounts } from './provenanceCountsRefresh';

const setVisibility = (state: DocumentVisibilityState) => {
  vi.spyOn(document, 'visibilityState', 'get').mockReturnValue(state);
  document.dispatchEvent(new Event('visibilitychange'));
};

describe('provenance counts refresh', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('gives every count a new fetch key after a provenance action', () => {
    const badge = renderHook(() => useProvenanceCountsFetchKey());
    const counters = renderHook(() => useProvenanceCountsFetchKey());
    const before = badge.result.current;
    expect(counters.result.current).toEqual(before);
    act(() => refreshProvenanceCounts());
    expect(badge.result.current).not.toEqual(before);
    expect(counters.result.current).toEqual(badge.result.current);
    badge.unmount();
    counters.unmount();
  });

  it('reads the counts again on the timer while the page is visible', () => {
    setVisibility('visible');
    const { result, unmount } = renderHook(() => useProvenanceCountsFetchKey());
    const before = result.current;
    act(() => {
      vi.advanceTimersByTime(PROVENANCE_COUNTS_REFRESH_INTERVAL_MS - 1);
    });
    expect(result.current).toEqual(before);
    act(() => {
      vi.advanceTimersByTime(1);
    });
    expect(result.current).not.toEqual(before);
    unmount();
  });

  it('skips the timer while the page is hidden and catches up once when it is visible again', () => {
    setVisibility('visible');
    const { result, unmount } = renderHook(() => useProvenanceCountsFetchKey());
    const before = result.current;
    act(() => {
      setVisibility('hidden');
      vi.advanceTimersByTime(PROVENANCE_COUNTS_REFRESH_INTERVAL_MS);
    });
    expect(result.current).toEqual(before);
    act(() => setVisibility('visible'));
    const caughtUp = result.current;
    expect(caughtUp).not.toEqual(before);
    // Back and forth without a missed tick reads nothing again
    act(() => {
      setVisibility('hidden');
      setVisibility('visible');
    });
    expect(result.current).toEqual(caughtUp);
    unmount();
  });

  it('leaves no timer once no count is shown', () => {
    const first = renderHook(() => useProvenanceCountsFetchKey());
    const second = renderHook(() => useProvenanceCountsFetchKey());
    expect(vi.getTimerCount()).toEqual(1);
    first.unmount();
    expect(vi.getTimerCount()).toEqual(1);
    second.unmount();
    expect(vi.getTimerCount()).toEqual(0);
  });
});
