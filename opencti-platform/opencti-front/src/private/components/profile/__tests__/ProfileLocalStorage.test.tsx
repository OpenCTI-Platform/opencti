import React from 'react';
import { afterEach, describe, expect, it } from 'vitest';
import { act, renderHook, screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import useSearchShortcut, { writeSearchShortcut } from '../../../../utils/hooks/useSearchShortcut';
import { DEFAULT_SEARCH_SHORTCUT } from '../../../../utils/searchShortcut';
import ProfileLocalStorage from '../ProfileLocalStorage';

describe('ProfileLocalStorage', () => {
  afterEach(() => localStorage.clear());

  it('clears the local settings, and the search shortcut follows at once', async () => {
    const { result } = renderHook(() => useSearchShortcut());
    act(() => writeSearchShortcut({ key: 'k', ctrl: true, meta: false, shift: false }));
    expect(result.current).toEqual({ key: 'k', ctrl: true, meta: false, shift: false });

    const { user } = testRender(<ProfileLocalStorage />);
    await user.click(screen.getByRole('button', { name: 'Clear local storage' }));
    await user.click(screen.getByRole('button', { name: 'Validate' }));

    expect(localStorage.getItem('search-shortcut')).toBeNull();
    expect(result.current).toEqual(DEFAULT_SEARCH_SHORTCUT);
  });
});
