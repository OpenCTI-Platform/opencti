import { describe, expect, it, vi } from 'vitest';
import { act, renderHook } from '@testing-library/react';
import { getEntityEditionOpener, registerEntityEditionOpener, useEntityEditionOpener } from './entityEditionOpener';

describe('entityEditionOpener', () => {
  it('returns null when nothing is registered', () => {
    expect(getEntityEditionOpener()).toBeNull();
  });

  it('returns the latest registered opener and falls back on unregister', () => {
    const first = vi.fn();
    const second = vi.fn();
    const offFirst = registerEntityEditionOpener(first);
    const offSecond = registerEntityEditionOpener(second);
    getEntityEditionOpener()?.();
    expect(second).toHaveBeenCalledTimes(1);
    expect(first).not.toHaveBeenCalled();
    offSecond();
    getEntityEditionOpener()?.();
    expect(first).toHaveBeenCalledTimes(1);
    offFirst();
    expect(getEntityEditionOpener()).toBeNull();
  });

  it('unregistering twice does not remove another opener', () => {
    const offFirst = registerEntityEditionOpener(vi.fn());
    const offSecond = registerEntityEditionOpener(vi.fn());
    offSecond();
    offSecond();
    expect(getEntityEditionOpener()).not.toBeNull();
    offFirst();
    expect(getEntityEditionOpener()).toBeNull();
  });

  it('re-renders the hook on register and unregister', () => {
    const { result } = renderHook(() => useEntityEditionOpener());
    expect(result.current).toBeNull();
    const open = vi.fn();
    let off = () => {};
    act(() => {
      off = registerEntityEditionOpener(open);
    });
    result.current?.();
    expect(open).toHaveBeenCalledTimes(1);
    act(() => off());
    expect(result.current).toBeNull();
  });
});
