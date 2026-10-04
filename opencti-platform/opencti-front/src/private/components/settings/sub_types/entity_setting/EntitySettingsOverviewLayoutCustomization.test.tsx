import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, screen, within } from '@testing-library/react';
import testRender from '../../../../../utils/tests/test-render';
import EntitySettingsOverviewLayoutCustomization from './EntitySettingsOverviewLayoutCustomization';
import { MESSAGING$ } from '../../../../../relay/environment';

const mockCommit = vi.fn();
vi.mock('../../../../../utils/hooks/useApiMutation', () => ({
  default: () => [mockCommit, false],
}));

const TIMELINE = { key: 'timeline', width: 6, label: 'Timeline' };
const DETAILS = { key: 'details', width: 6, label: 'Entity details' };
const NOTES = { key: 'notes', width: 12, label: 'Notes about this entity' };
const DEFAULT_LAYOUT = [TIMELINE, DETAILS, NOTES].map(({ key, width }) => ({ key, width }));

const renderLayout = (layout: { key: string; width: number; label: string }[]) => testRender(
  <EntitySettingsOverviewLayoutCustomization
    entitySettingsData={{ id: 'entity-setting-id', overview_layout_customization: layout, defaultOverviewLayoutCustomization: DEFAULT_LAYOUT }}
  />,
);

const committedLayout = () => mockCommit.mock.lastCall?.[0].variables.input;

describe('EntitySettingsOverviewLayoutCustomization', () => {
  beforeEach(() => {
    mockCommit.mockClear();
  });

  it('lists the widgets in the order, widget, displayed, full width columns', () => {
    renderLayout([TIMELINE, DETAILS, NOTES]);
    const [header, ...rows] = screen.getAllByRole('row');
    expect(within(header).getAllByRole('columnheader').map((cell) => cell.textContent)).toEqual(['Order', 'Widget', 'Displayed', 'Full width']);
    expect(rows.map((row) => within(row).getAllByRole('cell')[0].textContent)).toEqual(['Timeline', 'Entity details', 'Notes about this entity']);
    expect(screen.getByRole('switch', { name: 'Display Timeline' })).toBeChecked();
    expect(screen.getByRole('switch', { name: 'Show Timeline at full width' })).not.toBeChecked();
    expect(screen.getByRole('switch', { name: 'Show Notes about this entity at full width' })).toBeChecked();
  });

  it('hides a widget by storing it with a width of 0 at the same place', async () => {
    const { user } = renderLayout([TIMELINE, DETAILS, NOTES]);
    await user.click(screen.getByRole('switch', { name: 'Display Timeline' }));
    expect(committedLayout()).toEqual({
      key: 'overview_layout_customization',
      value: [{ ...TIMELINE, width: 0 }, DETAILS, NOTES],
    });
  });

  it('keeps a hidden widget in place and explains why its width cannot be chosen', async () => {
    renderLayout([DETAILS, { ...TIMELINE, width: 0 }, NOTES]);
    expect(screen.getByRole('switch', { name: 'Display Timeline' })).not.toBeChecked();
    const fullWidth = screen.getByRole('switch', { name: 'Show Timeline at full width' });
    expect(fullWidth).not.toBeChecked();
    expect(fullWidth).toBeDisabled();
    act(() => {
      fullWidth.parentElement?.focus();
    });
    expect(await screen.findByRole('tooltip')).toHaveTextContent('Display the widget to choose its width');
  });

  it('gives its default width back to a widget displayed again', async () => {
    const { user } = renderLayout([DETAILS, { ...TIMELINE, width: 0 }, { ...NOTES, width: 0 }]);
    await user.click(screen.getByRole('switch', { name: 'Display Notes about this entity' }));
    expect(committedLayout().value).toEqual([DETAILS, { ...TIMELINE, width: 0 }, NOTES]);
  });

  it('displays again at half of the width a widget without default width', async () => {
    const custom = { key: 'custom', width: 0, label: 'Custom' };
    const { user } = renderLayout([DETAILS, custom]);
    await user.click(screen.getByRole('switch', { name: 'Display Custom' }));
    expect(committedLayout().value).toEqual([DETAILS, { ...custom, width: 6 }]);
  });

  it('resizes a widget without changing the others', async () => {
    const { user } = renderLayout([TIMELINE, DETAILS, NOTES]);
    await user.click(screen.getByRole('switch', { name: 'Show Timeline at full width' }));
    expect(committedLayout().value).toEqual([{ ...TIMELINE, width: 12 }, DETAILS, NOTES]);
  });

  it('tells the administrator why a change was refused and keeps the stored layout', async () => {
    const notifyError = vi.spyOn(MESSAGING$, 'notifyError').mockImplementation(() => {});
    const { user } = renderLayout([TIMELINE, DETAILS, NOTES]);
    await user.click(screen.getByRole('switch', { name: 'Display Timeline' }));
    act(() => {
      mockCommit.mock.lastCall?.[0].onCompleted(null, [{ message: 'You are not allowed to do this.' }]);
    });
    expect(notifyError).toHaveBeenCalledWith('You are not allowed to do this.');
    expect(screen.getByRole('switch', { name: 'Display Timeline' })).toBeChecked();
    notifyError.mockRestore();
  });
});
