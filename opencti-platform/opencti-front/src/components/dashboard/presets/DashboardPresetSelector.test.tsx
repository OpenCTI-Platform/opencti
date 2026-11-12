import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import type { DashboardPreset } from '../dashboard-types';
import DashboardPresetSelector from './DashboardPresetSelector';

const range = { startDate: null, endDate: null, relativeDate: null };
const presets: DashboardPreset[] = [
  { id: 'energy', name: 'Energy', values: {}, config: range },
  { id: 'finance', name: 'Finance', values: {}, config: range },
];
const noop = () => {};

describe('DashboardPresetSelector', () => {
  it('shows the active preset in the pill and marks the default one in the menu', async () => {
    const { user } = testRender(
      <DashboardPresetSelector presets={presets} activePreset={presets[0]} defaultPreset={presets[1]} onSelect={noop} />,
    );
    expect(screen.getByTestId('dashboard-preset-trigger')).toHaveTextContent('PresetEnergy');
    await user.click(screen.getByTestId('dashboard-preset-trigger'));
    expect(await screen.findByTestId('dashboard-preset-option-finance')).toHaveTextContent('FinanceDefault');
    expect(screen.getByTestId('dashboard-preset-option-energy')).not.toHaveTextContent('Default');
    // With a default preset, picking it already leaves the others: no separate entry for no preset.
    expect(screen.queryByTestId('dashboard-preset-none')).not.toBeInTheDocument();
    // A viewer gets no management entry.
    expect(screen.queryByTestId('dashboard-preset-rename')).not.toBeInTheDocument();
    expect(screen.queryByTestId('dashboard-preset-delete')).not.toBeInTheDocument();
  });

  it('reports the selected preset, or none', async () => {
    const onSelect = vi.fn();
    const { user } = testRender(
      <DashboardPresetSelector presets={presets} activePreset={presets[0]} defaultPreset={null} onSelect={onSelect} />,
    );
    await user.click(screen.getByTestId('dashboard-preset-trigger'));
    await user.click(await screen.findByTestId('dashboard-preset-option-finance'));
    expect(onSelect).toHaveBeenCalledExactlyOnceWith('finance');
    onSelect.mockClear();
    await user.click(screen.getByTestId('dashboard-preset-trigger'));
    await user.click(await screen.findByTestId('dashboard-preset-none'));
    expect(onSelect).toHaveBeenCalledExactlyOnceWith(null);
  });

  it('shows No preset in the pill when none is active', () => {
    testRender(<DashboardPresetSelector presets={presets} activePreset={null} defaultPreset={null} onSelect={noop} />);
    expect(screen.getByTestId('dashboard-preset-trigger')).toHaveTextContent('PresetNo preset');
  });

  it('offers the editor to rename and delete the active preset, by name', async () => {
    const onRename = vi.fn();
    const onDelete = vi.fn();
    const { user } = testRender(
      <DashboardPresetSelector presets={presets} activePreset={presets[0]} defaultPreset={null} onSelect={noop} onRename={onRename} onDelete={onDelete} />,
    );
    await user.click(screen.getByTestId('dashboard-preset-trigger'));
    const rename = await screen.findByTestId('dashboard-preset-rename');
    expect(rename).toHaveTextContent('Rename “Energy”');
    await user.click(rename);
    expect(onRename).toHaveBeenCalledExactlyOnceWith(presets[0]);
    await user.click(screen.getByTestId('dashboard-preset-trigger'));
    const remove = await screen.findByTestId('dashboard-preset-delete');
    expect(remove).toHaveTextContent('Delete “Energy”');
    await user.click(remove);
    expect(onDelete).toHaveBeenCalledExactlyOnceWith(presets[0]);
  });

  it('offers no management without an active preset', async () => {
    const { user } = testRender(
      <DashboardPresetSelector presets={presets} activePreset={null} defaultPreset={null} onSelect={noop} onRename={noop} onDelete={noop} />,
    );
    await user.click(screen.getByTestId('dashboard-preset-trigger'));
    await screen.findByTestId('dashboard-preset-option-energy');
    expect(screen.queryByTestId('dashboard-preset-rename')).not.toBeInTheDocument();
    expect(screen.queryByTestId('dashboard-preset-delete')).not.toBeInTheDocument();
  });

  it('renders nothing when the dashboard has no preset yet', () => {
    testRender(<DashboardPresetSelector presets={[]} activePreset={null} defaultPreset={null} onSelect={noop} onRename={noop} />);
    expect(screen.queryByTestId('dashboard-preset-selector')).not.toBeInTheDocument();
  });
});
