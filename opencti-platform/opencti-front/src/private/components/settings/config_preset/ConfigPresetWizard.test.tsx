import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, screen, within } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import ConfigPresetWizard from './ConfigPresetWizard';

describe('ConfigPresetWizard', () => {
  const onClose = vi.fn();

  beforeEach(() => {
    onClose.mockReset();
  });

  it('shows the two choices disabled, the import one with its test id', () => {
    testRender(<ConfigPresetWizard mode="auto" onClose={onClose} />);
    expect(screen.getByText('Set up your platform')).toBeInTheDocument();
    expect(screen.getByTestId('config-preset-wizard-import')).toHaveTextContent('Import a configuration');
    expect(within(screen.getByTestId('config-preset-wizard-import')).getByRole('button')).toBeDisabled();
    expect(within(screen.getByTestId('config-preset-wizard-template')).getByRole('button')).toBeDisabled();
    expect(screen.getByText('Coming later')).toBeInTheDocument();
  });

  it('renders the step it is given instead of the welcome choices', () => {
    testRender(<ConfigPresetWizard mode="auto" onClose={onClose}><div>Upload step</div></ConfigPresetWizard>);
    expect(screen.getByText('Upload step')).toBeInTheDocument();
    expect(screen.queryByTestId('config-preset-wizard-import')).not.toBeInTheDocument();
  });

  it.each(['Skip', 'Close'])('stores the skip on the user with %s in auto mode', async (name) => {
    const { user, relayEnv } = testRender(<ConfigPresetWizard mode="auto" onClose={onClose} />);
    await user.click(screen.getByRole('button', { name }));
    const [operation] = relayEnv.mock.getAllOperations();
    expect(operation.request.node.operation.name).toEqual('ConfigPresetWizardSkipMutation');
    expect(operation.request.variables).toEqual({ input: { key: 'bootstrap_wizard_skipped', value: [true] } });
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('closes anyway when the skip write fails', async () => {
    const { user, relayEnv } = testRender(<ConfigPresetWizard mode="auto" onClose={onClose} />);
    await user.click(screen.getByRole('button', { name: 'Skip' }));
    await act(async () => {
      relayEnv.mock.rejectMostRecentOperation({ res: { errors: [{ message: 'write failed' }] } } as unknown as Error);
    });
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('writes nothing in manual mode', async () => {
    const { user, relayEnv } = testRender(<ConfigPresetWizard mode="manual" onClose={onClose} />);
    await user.click(screen.getByRole('button', { name: 'Skip' }));
    expect(relayEnv.mock.getAllOperations()).toHaveLength(0);
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('does not close on Escape', async () => {
    const { user } = testRender(<ConfigPresetWizard mode="auto" onClose={onClose} />);
    await user.keyboard('{Escape}');
    expect(onClose).not.toHaveBeenCalled();
    expect(screen.getByText('Set up your platform')).toBeInTheDocument();
  });
});
