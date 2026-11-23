import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { act, screen } from '@testing-library/react';
import testRender from '../../utils/tests/test-render';
import { EXPORT_REMOVE_CLASS } from '../../utils/Image';
import DashboardSaveMenu from './DashboardSaveMenu';

describe('DashboardSaveMenu', () => {
  it('groups the entries by whom they write for', async () => {
    const { user } = testRender(
      <DashboardSaveMenu
        activePresetName="Finance"
        canUpdatePreset
        canSetAsDefaults
        onUpdatePreset={vi.fn()}
        onSavePresetAs={vi.fn()}
        onSetAsDefaults={vi.fn()}
      />,
    );
    expect(screen.getByTestId('dashboard-save-menu')).toHaveClass(EXPORT_REMOVE_CLASS);
    await user.click(screen.getByTestId('dashboard-save-menu'));
    // Each entry says for whom it writes, under its action
    expect(await screen.findByTestId('dashboard-preset-update')).toHaveTextContent('Update “Finance”For everyone using this preset');
    expect(screen.getByTestId('dashboard-preset-save-as')).toHaveTextContent('Save as new preset…Under a new name, for anyone to pick');
    expect(screen.getByTestId('dashboard-set-as-defaults')).toHaveTextContent('Set as dashboard defaultsFor everyone without a preset');
  });

  it('calls the picked entry', async () => {
    const onUpdatePreset = vi.fn();
    const onSavePresetAs = vi.fn();
    const onSetAsDefaults = vi.fn();
    const { user } = testRender(
      <DashboardSaveMenu
        activePresetName="Finance"
        canUpdatePreset
        canSetAsDefaults
        onUpdatePreset={onUpdatePreset}
        onSavePresetAs={onSavePresetAs}
        onSetAsDefaults={onSetAsDefaults}
      />,
    );
    await user.click(screen.getByTestId('dashboard-save-menu'));
    await user.click(await screen.findByTestId('dashboard-preset-update'));
    expect(onUpdatePreset).toHaveBeenCalledOnce();
    await user.click(screen.getByTestId('dashboard-save-menu'));
    await user.click(await screen.findByTestId('dashboard-preset-save-as'));
    expect(onSavePresetAs).toHaveBeenCalledOnce();
    await user.click(screen.getByTestId('dashboard-save-menu'));
    await user.click(await screen.findByTestId('dashboard-set-as-defaults'));
    expect(onSetAsDefaults).toHaveBeenCalledOnce();
  });

  it('stays closed once an entry is picked, while the save it starts disables the menu', async () => {
    // As on the page: the picked entry starts a save that disables the menu, then the save ends.
    let endSave: () => void = () => {};
    const Page = () => {
      const [saving, setSaving] = React.useState(false);
      const save = () => {
        setSaving(true);
        endSave = () => act(() => setSaving(false));
      };
      return <DashboardSaveMenu activePresetName="Finance" canUpdatePreset canSetAsDefaults disabled={saving} onUpdatePreset={save} onSavePresetAs={vi.fn()} onSetAsDefaults={save} />;
    };
    const { user } = testRender(<Page />);
    await user.click(screen.getByTestId('dashboard-save-menu'));
    await user.click(await screen.findByTestId('dashboard-set-as-defaults'));
    endSave();
    await new Promise((resolve) => {
      setTimeout(resolve, 50);
    });
    expect(screen.queryByTestId('dashboard-set-as-defaults')).toBeNull();
  });

  it('disables the writes that would change nothing', async () => {
    const { user } = testRender(
      <DashboardSaveMenu
        activePresetName="Finance"
        canUpdatePreset={false}
        canSetAsDefaults={false}
        onUpdatePreset={vi.fn()}
        onSavePresetAs={vi.fn()}
        onSetAsDefaults={vi.fn()}
      />,
    );
    await user.click(screen.getByTestId('dashboard-save-menu'));
    expect(await screen.findByTestId('dashboard-preset-update')).toHaveAttribute('data-disabled');
    expect(screen.getByTestId('dashboard-set-as-defaults')).toHaveAttribute('data-disabled');
    expect(screen.getByTestId('dashboard-preset-save-as')).not.toHaveAttribute('data-disabled');
  });

  it('offers no update without an active preset', async () => {
    const { user } = testRender(
      <DashboardSaveMenu canUpdatePreset={false} canSetAsDefaults onUpdatePreset={vi.fn()} onSavePresetAs={vi.fn()} onSetAsDefaults={vi.fn()} />,
    );
    await user.click(screen.getByTestId('dashboard-save-menu'));
    await screen.findByTestId('dashboard-preset-save-as');
    expect(screen.queryByTestId('dashboard-preset-update')).not.toBeInTheDocument();
  });

  it('renders nothing without any entry', () => {
    testRender(<DashboardSaveMenu canUpdatePreset={false} canSetAsDefaults={false} />);
    expect(screen.queryByTestId('dashboard-save-menu')).not.toBeInTheDocument();
  });
});
