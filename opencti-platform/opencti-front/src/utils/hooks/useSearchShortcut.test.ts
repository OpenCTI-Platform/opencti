import { afterEach, describe, expect, it } from 'vitest';
import { act, renderHook } from '@testing-library/react';
import useSearchShortcut, { writeSearchShortcut } from './useSearchShortcut';
import { DEFAULT_SEARCH_SHORTCUT } from '../searchShortcut';

describe('Hook: useSearchShortcut', () => {
  afterEach(() => localStorage.clear());

  it('is the default until the user chooses another one, and follows the change at once', () => {
    const { result } = renderHook(() => useSearchShortcut());
    expect(result.current).toEqual(DEFAULT_SEARCH_SHORTCUT);

    const ctrlK = { key: 'k', ctrl: true, meta: false, shift: false };
    act(() => writeSearchShortcut(ctrlK));
    expect(result.current).toEqual(ctrlK);
  });

  it('can be turned off, and turned back to the default', () => {
    const { result } = renderHook(() => useSearchShortcut());
    act(() => writeSearchShortcut(null));
    expect(result.current).toBeNull();

    act(() => writeSearchShortcut(DEFAULT_SEARCH_SHORTCUT));
    expect(result.current).toEqual(DEFAULT_SEARCH_SHORTCUT);
  });
});
