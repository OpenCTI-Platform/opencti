import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../utils/tests/test-render';
import FilterIconButtonGlobalMode from './FilterIconButtonGlobalMode';

describe('FilterIconButtonGlobalMode', () => {
  it('switches the mode from the keyboard, as a tab stop', async () => {
    const handleSwitchGlobalMode = vi.fn();
    const { user } = testRender(
      <FilterIconButtonGlobalMode operatorStyle={{}} globalMode="and" isOperatorClickable handleSwitchGlobalMode={handleSwitchGlobalMode} />,
    );

    await user.tab();
    expect(screen.getByRole('button', { name: 'and' })).toHaveFocus();
    await user.keyboard('{Enter}');
    await user.keyboard(' ');
    expect(handleSwitchGlobalMode).toHaveBeenCalledTimes(2);
  });

  it('renders the mode of a read-only filter as plain text, not as a button', async () => {
    const handleSwitchGlobalMode = vi.fn();
    const { user } = testRender(
      <FilterIconButtonGlobalMode operatorStyle={{}} globalMode="or" isOperatorClickable={false} handleSwitchGlobalMode={handleSwitchGlobalMode} />,
    );

    expect(screen.queryByRole('button')).not.toBeInTheDocument();
    await user.click(screen.getByText('or'));
    expect(handleSwitchGlobalMode).not.toHaveBeenCalled();
  });
});
