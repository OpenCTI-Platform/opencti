import React from 'react';
import { afterEach, describe, expect, it } from 'vitest';
import { act, fireEvent, render } from '@testing-library/react';
import useFocusSearchShortcut from './useFocusSearchShortcut';
import { writeSearchShortcut } from '../../../utils/hooks/useSearchShortcut';
import { TOP_BAR_SEARCH_ID } from '../../../utils/searchShortcut';

const Page = ({ withSearch = true, children }: { withSearch?: boolean; children?: React.ReactNode }) => {
  useFocusSearchShortcut();
  return (
    <>
      {withSearch && <input id={TOP_BAR_SEARCH_ID} defaultValue="previous search" />}
      <input data-testid="other" />
      {children}
    </>
  );
};

const searchField = () => document.getElementById(TOP_BAR_SEARCH_ID);

describe('Hook: useFocusSearchShortcut', () => {
  afterEach(() => localStorage.clear());

  it('focuses the search field, text selected, on the default "/"', () => {
    render(<Page />);
    expect(fireEvent.keyDown(document.body, { key: '/' })).toBe(false); // default prevented: no "/" typed anywhere
    expect(searchField()).toHaveFocus();
    expect((searchField() as HTMLInputElement).selectionEnd).toBe('previous search'.length);
  });

  it('leaves a "/" typed in another field alone', () => {
    const { getByTestId } = render(<Page />);
    const other = getByTestId('other');
    other.focus();
    expect(fireEvent.keyDown(other, { key: '/' })).toBe(true);
    expect(other).toHaveFocus();
  });

  it('ignores a key already answered by someone else (the graph owns "/" while hovered)', () => {
    render(<Page />);
    document.addEventListener('keydown', (event) => event.preventDefault(), { once: true });
    fireEvent.keyDown(document.body, { key: '/' });
    expect(searchField()).not.toHaveFocus();
  });

  it('ignores the key while a dialog is open, and while an IME composes', () => {
    render(<Page><div role="dialog" aria-modal="true" /></Page>);
    fireEvent.keyDown(document.body, { key: '/' });
    expect(searchField()).not.toHaveFocus();
  });

  it('ignores an IME confirmation', () => {
    render(<Page />);
    fireEvent.keyDown(document.body, { key: '/', keyCode: 229 });
    expect(searchField()).not.toHaveFocus();
  });

  it('does nothing, and does not swallow the key, when there is no search field (no knowledge access)', () => {
    render(<Page withSearch={false} />);
    expect(fireEvent.keyDown(document.body, { key: '/' })).toBe(true);
  });

  it('follows the user choice: a Ctrl shortcut works even while typing in another field, the default no longer does', () => {
    const { getByTestId } = render(<Page />);
    act(() => writeSearchShortcut({ key: 'k', ctrl: true, meta: false, shift: false }));

    const other = getByTestId('other');
    other.focus();
    fireEvent.keyDown(other, { key: '/' });
    expect(other).toHaveFocus();
    fireEvent.keyDown(other, { key: 'k', ctrlKey: true });
    expect(searchField()).toHaveFocus();
  });

  it('does nothing once the user turned the shortcut off', () => {
    render(<Page />);
    act(() => writeSearchShortcut(null));
    fireEvent.keyDown(document.body, { key: '/' });
    expect(searchField()).not.toHaveFocus();
  });
});
