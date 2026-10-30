import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen, within } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import ConfigPresetWizardWelcome from './ConfigPresetWizardWelcome';

describe('ConfigPresetWizardWelcome', () => {
  it('shows the four templates disabled, as coming later, and a disabled Next', () => {
    testRender(<ConfigPresetWizardWelcome />);
    const templates = within(screen.getByTestId('config-preset-wizard-template')).getAllByRole('button');
    expect(templates).toHaveLength(4);
    templates.forEach((template) => expect(template).toBeDisabled());
    ['Classic CTI', 'FIMI/Disinformation', 'Fraud Prevention', 'Incident Management'].forEach((name) => expect(screen.getByText(name)).toBeInTheDocument());
    expect(screen.getAllByText('Coming later')).toHaveLength(4);
    expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled();
  });

  it('disables Import config without handler and enables it with one', async () => {
    const { unmount } = testRender(<ConfigPresetWizardWelcome />);
    expect(screen.getByRole('button', { name: 'Import config' })).toBeDisabled();
    unmount();
    const onImport = vi.fn();
    const { user } = testRender(<ConfigPresetWizardWelcome onImport={onImport} />);
    await user.click(screen.getByRole('button', { name: 'Import config' }));
    expect(onImport).toHaveBeenCalledTimes(1);
  });
});
