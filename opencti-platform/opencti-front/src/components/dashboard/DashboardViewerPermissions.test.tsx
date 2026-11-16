import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../utils/tests/test-render';
import DashboardViewerPermissions from './DashboardViewerPermissions';

describe('DashboardViewerPermissions', () => {
  it('shows the three switches on when the keys are absent: viewers may change everything unless the editor closes a switch', () => {
    testRender(<DashboardViewerPermissions config={{ relativeDate: 'days-7' }} onChange={vi.fn()} />);
    const switches = screen.getAllByRole('switch');
    expect(switches).toHaveLength(3);
    switches.forEach((element) => expect(element).toBeChecked());
  });

  it('shows a switch off only when its key is false', () => {
    testRender(<DashboardViewerPermissions config={{ allowViewersToChangeVariables: false }} onChange={vi.fn()} />);
    expect(screen.getByRole('switch', { name: 'Allow viewers to change variable values' })).not.toBeChecked();
    expect(screen.getByRole('switch', { name: 'Allow viewers to edit time filters' })).toBeChecked();
    expect(screen.getByRole('switch', { name: 'Allow viewers to switch presets' })).toBeChecked();
  });

  it('reports the presets switch on its own', async () => {
    const onChange = vi.fn();
    const { user } = testRender(<DashboardViewerPermissions config={{}} onChange={onChange} />);
    await user.click(screen.getByRole('switch', { name: 'Allow viewers to switch presets' }));
    expect(onChange).toHaveBeenCalledExactlyOnceWith({ allowViewersToSwitchPresets: false });
  });

  it('reports only the switched key', async () => {
    const onChange = vi.fn();
    const { user } = testRender(<DashboardViewerPermissions config={{}} onChange={onChange} />);
    await user.click(screen.getByRole('switch', { name: 'Allow viewers to edit time filters' }));
    expect(onChange).toHaveBeenCalledExactlyOnceWith({ allowViewersToEditTimeFilters: false });
  });

  it('disables only the switches being saved', () => {
    testRender(<DashboardViewerPermissions config={{}} pending={['allowViewersToChangeVariables']} onChange={vi.fn()} />);
    expect(screen.getByRole('switch', { name: 'Allow viewers to change variable values' })).toBeDisabled();
    expect(screen.getByRole('switch', { name: 'Allow viewers to edit time filters' })).toBeEnabled();
  });
});
