import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, within } from '@testing-library/react';
import testRender from '../../../../../utils/tests/test-render';
import EntitySettingsOverviewLayoutCustomization from './EntitySettingsOverviewLayoutCustomization';

const mockCommit = vi.fn();
vi.mock('../../../../../utils/hooks/useApiMutation', () => ({
  default: () => [mockCommit, false],
}));

const TIMELINE = { key: 'timeline', width: 12, label: 'Timeline' };
const DETAILS = { key: 'details', width: 6, label: 'Entity details' };
const NOTES = { key: 'notes', width: 12, label: 'Notes about this entity' };

const renderLayout = (layout: { key: string; width: number; label: string }[]) => testRender(
  <EntitySettingsOverviewLayoutCustomization entitySettingsData={{ id: 'entity-setting-id', overview_layout_customization: layout }} />,
);

const committedLayout = () => mockCommit.mock.lastCall?.[0].variables.input;

describe('EntitySettingsOverviewLayoutCustomization', () => {
  beforeEach(() => {
    mockCommit.mockClear();
  });

  it('lists the timeline widget, displayed and full width', () => {
    renderLayout([TIMELINE, DETAILS, NOTES]);
    const rows = screen.getAllByRole('row').slice(1);
    expect(rows.map((row) => within(row).getAllByRole('cell')[0].textContent)).toEqual(['Timeline', 'Entity details', 'Notes about this entity']);
    expect(screen.getByRole('switch', { name: 'Display Timeline' })).toBeChecked();
    expect(screen.getByRole('switch', { name: 'Display Timeline in full width' })).toBeChecked();
    expect(screen.getByRole('switch', { name: 'Display Entity details in full width' })).not.toBeChecked();
  });

  it('hides a widget by storing it with a width of 0 at the same place', async () => {
    const { user } = renderLayout([TIMELINE, DETAILS, NOTES]);
    await user.click(screen.getByRole('switch', { name: 'Display Timeline' }));
    expect(committedLayout()).toEqual({
      key: 'overview_layout_customization',
      value: [{ ...TIMELINE, width: 0 }, DETAILS, NOTES],
    });
  });

  it('shows a hidden widget as hidden and displays it again on half of the width', async () => {
    const { user } = renderLayout([DETAILS, { ...TIMELINE, width: 0 }, NOTES]);
    expect(screen.getByRole('switch', { name: 'Display Timeline' })).not.toBeChecked();
    const fullWidth = screen.getByRole('switch', { name: 'Display Timeline in full width' });
    expect(fullWidth).not.toBeChecked();
    expect(fullWidth).toBeDisabled();
    await user.click(screen.getByRole('switch', { name: 'Display Timeline' }));
    expect(committedLayout().value).toEqual([DETAILS, { ...TIMELINE, width: 6 }, NOTES]);
  });

  it('resizes a widget without changing the others', async () => {
    const { user } = renderLayout([TIMELINE, DETAILS, NOTES]);
    await user.click(screen.getByRole('switch', { name: 'Display Timeline in full width' }));
    expect(committedLayout().value).toEqual([{ ...TIMELINE, width: 6 }, DETAILS, NOTES]);
  });
});
