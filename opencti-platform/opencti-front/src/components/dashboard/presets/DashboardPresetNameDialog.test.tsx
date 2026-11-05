import { describe, expect, it, vi } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import type { DashboardPreset } from '../dashboard-types';
import DashboardPresetNameDialog from './DashboardPresetNameDialog';

const range = { startDate: null, endDate: null, relativeDate: null };
const existing: DashboardPreset[] = [{ id: 'energy', name: 'Energy', values: {}, config: range }];

describe('DashboardPresetNameDialog', () => {
  it('refuses an empty or duplicated name and confirms a valid one', async () => {
    const onConfirm = vi.fn().mockResolvedValue(undefined);
    const onClose = vi.fn();
    const { user } = testRender(<DashboardPresetNameDialog open existingPresets={existing} onConfirm={onConfirm} onClose={onClose} />);
    const confirm = screen.getByTestId('dashboard-preset-name-confirm');
    expect(confirm).toBeDisabled();
    await user.type(screen.getByLabelText(/Preset name/), ' energy ');
    expect(await screen.findByText('A preset with this name already exists')).toBeInTheDocument();
    expect(confirm).toBeDisabled();
    await user.clear(screen.getByLabelText(/Preset name/));
    await user.type(screen.getByLabelText(/Preset name/), ' Finance ');
    await user.click(confirm);
    expect(onConfirm).toHaveBeenCalledWith('Finance');
    await waitFor(() => expect(onClose).toHaveBeenCalled());
  });

  it('starts from the name of the renamed preset, which may keep it', async () => {
    const onConfirm = vi.fn().mockResolvedValue(undefined);
    const { user } = testRender(<DashboardPresetNameDialog open existingPresets={existing} preset={existing[0]} onConfirm={onConfirm} onClose={vi.fn()} />);
    expect(screen.getByLabelText(/Preset name/)).toHaveValue('Energy');
    expect(screen.getByTestId('dashboard-preset-name-confirm')).toBeEnabled();
    await user.click(screen.getByTestId('dashboard-preset-name-confirm'));
    expect(onConfirm).toHaveBeenCalledWith('Energy');
  });

  it('stays open when the confirmation fails', async () => {
    const onConfirm = vi.fn().mockRejectedValue(new Error('refused'));
    const onClose = vi.fn();
    const { user } = testRender(<DashboardPresetNameDialog open existingPresets={[]} onConfirm={onConfirm} onClose={onClose} />);
    await user.type(screen.getByLabelText(/Preset name/), 'Finance');
    await user.click(screen.getByTestId('dashboard-preset-name-confirm'));
    await waitFor(() => expect(onConfirm).toHaveBeenCalled());
    expect(onClose).not.toHaveBeenCalled();
    expect(screen.getByTestId('dashboard-preset-name-confirm')).toBeEnabled();
  });
});
