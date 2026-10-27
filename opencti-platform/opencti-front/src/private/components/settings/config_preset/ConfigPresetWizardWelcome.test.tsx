import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen, within } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import ConfigPresetWizardWelcome from './ConfigPresetWizardWelcome';

describe('ConfigPresetWizardWelcome', () => {
  it('shows the template choice as coming later, disabled', () => {
    testRender(<ConfigPresetWizardWelcome />);
    expect(within(screen.getByTestId('config-preset-wizard-template')).getByRole('button')).toBeDisabled();
    expect(screen.getByText('Coming later')).toBeInTheDocument();
  });

  it('disables the import choice without handler and enables it with one', async () => {
    const { unmount } = testRender(<ConfigPresetWizardWelcome />);
    expect(within(screen.getByTestId('config-preset-wizard-import')).getByRole('button')).toBeDisabled();
    unmount();
    const onImport = vi.fn();
    const { user } = testRender(<ConfigPresetWizardWelcome onImport={onImport} />);
    expect(screen.getByTestId('config-preset-wizard-import')).toHaveTextContent('Import a configuration');
    await user.click(within(screen.getByTestId('config-preset-wizard-import')).getByRole('button'));
    expect(onImport).toHaveBeenCalledTimes(1);
  });
});
