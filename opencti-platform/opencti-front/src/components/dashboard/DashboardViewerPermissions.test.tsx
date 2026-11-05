import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../utils/tests/test-render';
import DashboardViewerPermissions from './DashboardViewerPermissions';

describe('DashboardViewerPermissions', () => {
  it('shows the three switches off when the keys are absent', () => {
    testRender(<DashboardViewerPermissions config={{ relativeDate: 'days-7' }} onChange={vi.fn()} />);
    const switches = screen.getAllByRole('switch');
    expect(switches).toHaveLength(3);
    switches.forEach((element) => expect(element).not.toBeChecked());
  });

  it('shows a switch on when its key is set', () => {
    testRender(<DashboardViewerPermissions config={{ allowViewersToChangeVariables: true }} onChange={vi.fn()} />);
    expect(screen.getByRole('switch', { name: 'Allow viewers to change variable values' })).toBeChecked();
    expect(screen.getByRole('switch', { name: 'Allow viewers to edit time filters' })).not.toBeChecked();
    expect(screen.getByRole('switch', { name: 'Allow viewers to switch presets' })).not.toBeChecked();
  });

  it('reports the presets switch on its own', async () => {
    const onChange = vi.fn();
    const { user } = testRender(<DashboardViewerPermissions config={{}} onChange={onChange} />);
    await user.click(screen.getByRole('switch', { name: 'Allow viewers to switch presets' }));
    expect(onChange).toHaveBeenCalledExactlyOnceWith({ allowViewersToSwitchPresets: true });
  });

  it('reports only the switched key', async () => {
    const onChange = vi.fn();
    const { user } = testRender(<DashboardViewerPermissions config={{}} onChange={onChange} />);
    await user.click(screen.getByRole('switch', { name: 'Allow viewers to edit time filters' }));
    expect(onChange).toHaveBeenCalledExactlyOnceWith({ allowViewersToEditTimeFilters: true });
  });

  it('disables only the switches being saved', () => {
    testRender(<DashboardViewerPermissions config={{}} pending={['allowViewersToChangeVariables']} onChange={vi.fn()} />);
    expect(screen.getByRole('switch', { name: 'Allow viewers to change variable values' })).toBeDisabled();
    expect(screen.getByRole('switch', { name: 'Allow viewers to edit time filters' })).toBeEnabled();
  });
});
