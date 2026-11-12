import React from 'react';
import { afterEach, describe, expect, it } from 'vitest';
import { fireEvent, screen } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import ProfileSearchShortcut from './ProfileSearchShortcut';

const field = () => screen.getByLabelText('Search shortcut') as HTMLInputElement;

describe('ProfileSearchShortcut', () => {
  afterEach(() => localStorage.clear());

  it('shows the default shortcut, with nothing to reset', () => {
    testRender(<ProfileSearchShortcut />);
    expect(field()).toHaveValue('/');
    expect(screen.queryByRole('button', { name: 'Reset' })).not.toBeInTheDocument();
  });

  it('records the next key combination, and offers to reset it', () => {
    testRender(<ProfileSearchShortcut />);
    // returns false when the key was swallowed instead of typed
    expect(fireEvent.keyDown(field(), { key: 'k', ctrlKey: true })).toBe(false);

    expect(field()).toHaveValue('Ctrl+K');
    expect(screen.getByRole('button', { name: 'Reset' })).toBeInTheDocument();
  });

  it('refuses a key that cannot be a shortcut and keeps the previous one', () => {
    testRender(<ProfileSearchShortcut />);
    fireEvent.keyDown(field(), { key: 'k' });

    expect(field()).toHaveValue('/');
    expect(screen.getByText(/This key combination cannot be used/)).toBeInTheDocument();
  });

  it('lets Tab move on instead of recording it', () => {
    testRender(<ProfileSearchShortcut />);
    expect(fireEvent.keyDown(field(), { key: 'Tab' })).toBe(true);
    expect(field()).toHaveValue('/');
  });

  it('resets to the default, and turns the shortcut off', async () => {
    const { user } = testRender(<ProfileSearchShortcut />);
    fireEvent.keyDown(field(), { key: 'k', ctrlKey: true });
    await user.click(screen.getByRole('button', { name: 'Reset' }));
    expect(field()).toHaveValue('/');

    await user.click(screen.getByRole('button', { name: 'Disable' }));
    expect(field()).toHaveValue('');
    expect(field()).toHaveAttribute('placeholder', 'Disabled');
    expect(screen.queryByRole('button', { name: 'Disable' })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Reset' })).toBeInTheDocument();
  });
});
