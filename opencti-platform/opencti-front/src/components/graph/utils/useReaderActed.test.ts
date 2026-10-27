import { describe, expect, it, vi } from 'vitest';
import { renderHook } from '@testing-library/react';
import useReaderActed from './useReaderActed';

describe('useReaderActed', () => {
  it('remembers an action made while the data loads, and starts over when the mode changes', () => {
    const onAction = vi.fn();
    const { result, rerender, unmount } = renderHook(
      ({ mode3D }: { mode3D: boolean; loading: boolean }) => useReaderActed(mode3D, onAction),
      { initialProps: { mode3D: false, loading: true } },
    );
    expect(result.current.current).toBe(false);
    window.dispatchEvent(new Event('pointerdown'));
    expect(result.current.current).toBe(true);
    expect(onAction).toHaveBeenCalledTimes(1);
    // The data finished loading: what the reader did still counts.
    rerender({ mode3D: false, loading: false });
    expect(result.current.current).toBe(true);
    // A new mode is framed afresh, until the reader acts again.
    rerender({ mode3D: true, loading: false });
    expect(result.current.current).toBe(false);
    window.dispatchEvent(new KeyboardEvent('keydown'));
    expect(result.current.current).toBe(true);
    unmount();
    window.dispatchEvent(new Event('wheel'));
    expect(onAction).toHaveBeenCalledTimes(2);
  });
});
