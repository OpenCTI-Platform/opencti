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
  it('shows the active preset and marks the default one', async () => {
    const { user } = testRender(
      <DashboardPresetSelector presets={presets} activePreset={presets[0]} defaultPreset={presets[1]} isModified={false} canManage={false} onSelect={noop} />,
    );
    expect(screen.getByTestId('dashboard-preset-trigger')).toHaveTextContent('Energy');
    await user.click(screen.getByTestId('dashboard-preset-trigger'));
    expect(await screen.findByRole('option', { name: 'Finance (default)' })).toBeInTheDocument();
    expect(screen.getByRole('option', { name: 'No preset' })).toBeInTheDocument();
    // A viewer gets no action
    expect(screen.queryByTestId('dashboard-preset-save-as')).not.toBeInTheDocument();
    expect(screen.queryByTestId('dashboard-preset-delete')).not.toBeInTheDocument();
  });

  it('reports the selected preset, or none', async () => {
    const onSelect = vi.fn();
    const { user } = testRender(
      <DashboardPresetSelector presets={presets} activePreset={presets[0]} defaultPreset={null} isModified={false} canManage={false} onSelect={onSelect} />,
    );
    await user.click(screen.getByTestId('dashboard-preset-trigger'));
    await user.click(await screen.findByRole('option', { name: 'Finance' }));
    expect(onSelect).toHaveBeenCalledWith('finance');
    await user.click(screen.getByTestId('dashboard-preset-trigger'));
    await user.click(await screen.findByRole('option', { name: 'No preset' }));
    expect(onSelect).toHaveBeenLastCalledWith(null);
  });

  it('offers the editor actions, the update only when the preset is modified', async () => {
    const onUpdate = vi.fn();
    const onRename = vi.fn();
    const onDelete = vi.fn();
    const onSaveAs = vi.fn();
    const { user, rerender } = testRender(
      <DashboardPresetSelector
        presets={presets}
        activePreset={presets[0]}
        defaultPreset={null}
        isModified={false}
        canManage
        onSelect={noop}
        onSaveAs={onSaveAs}
        onUpdate={onUpdate}
        onRename={onRename}
        onDelete={onDelete}
      />,
    );
    expect(screen.queryByTestId('dashboard-preset-update')).not.toBeInTheDocument();
    await user.click(screen.getByTestId('dashboard-preset-save-as'));
    expect(onSaveAs).toHaveBeenCalledOnce();
    await user.click(screen.getByTestId('dashboard-preset-rename'));
    expect(onRename).toHaveBeenCalledWith(presets[0]);
    await user.click(screen.getByTestId('dashboard-preset-delete'));
    expect(onDelete).toHaveBeenCalledWith(presets[0]);
    rerender(
      <DashboardPresetSelector
        presets={presets}
        activePreset={presets[0]}
        defaultPreset={null}
        isModified
        canManage
        onSelect={noop}
        onSaveAs={onSaveAs}
        onUpdate={onUpdate}
        onRename={onRename}
        onDelete={onDelete}
      />,
    );
    await user.click(screen.getByTestId('dashboard-preset-update'));
    expect(onUpdate).toHaveBeenCalledOnce();
  });

  it('reserves the room the library clear control takes from the row (FDS-WORKAROUND #77)', () => {
    const { rerender } = testRender(
      <DashboardPresetSelector presets={presets} activePreset={presets[0]} defaultPreset={null} isModified={false} canManage onSelect={noop} onSaveAs={noop} />,
    );
    // With a value the trigger shows a clear control: its wrapper is 32px narrower than the trigger.
    expect(screen.getByTestId('dashboard-preset-select')).toHaveStyle({ paddingRight: '32px' });
    // Without a value (no clear control) or disabled (the library hides it), nothing to compensate.
    rerender(<DashboardPresetSelector presets={presets} activePreset={null} defaultPreset={null} isModified={false} canManage onSelect={noop} onSaveAs={noop} />);
    expect(screen.getByTestId('dashboard-preset-select')).toHaveStyle({ paddingRight: '0px' });
    rerender(<DashboardPresetSelector presets={presets} activePreset={presets[0]} defaultPreset={null} isModified={false} canManage disabled onSelect={noop} onSaveAs={noop} />);
    expect(screen.getByTestId('dashboard-preset-select')).toHaveStyle({ paddingRight: '0px' });
  });

  it('shows only the save action when the dashboard has no preset yet', () => {
    testRender(<DashboardPresetSelector presets={[]} activePreset={null} defaultPreset={null} isModified={false} canManage onSelect={noop} onSaveAs={noop} />);
    expect(screen.queryByTestId('dashboard-preset-trigger')).not.toBeInTheDocument();
    expect(screen.getByTestId('dashboard-preset-save-as')).toBeInTheDocument();
  });
});
