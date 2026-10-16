import React from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, screen, waitFor } from '@testing-library/react';
import { MockPayloadGenerator } from 'relay-test-utils';
import testRender from '../../../../utils/tests/test-render';
import ConfigPresetExportDrawer from './ConfigPresetExportDrawer';

const platformSettings = { id: 'platformSettings', label: 'Platform settings' };
const catalog = [
  { id: 'platform', label: 'Platform configuration', group: platformSettings, items: [{ id: 'platform', label: 'Platform configuration', translatable: true }] },
  { id: 'messages', label: 'Messages', group: platformSettings, items: [{ id: 'messages', label: 'Messages', translatable: true }] },
  {
    id: 'hiddenEntityTypes',
    label: 'Hidden entity types',
    group: { id: 'dataModel', label: 'Data model' },
    items: [{ id: 'hiddenEntityTypes', label: 'Hidden entity types', translatable: true }],
  },
];

// A type with several items, as entity-backed types will have: 'Observed datas' is an i18n key translated to 'Observed data'
const entityCatalog = [{
  id: 'observedData',
  label: 'Observed datas',
  group: platformSettings,
  items: [
    { id: 'static', label: 'Observed datas', translatable: true },
    { id: 'entity', label: 'Observed datas', translatable: false },
  ],
}];

const renderOpenDrawer = async (onClose = vi.fn(), types: unknown[] = catalog) => {
  const rendered = testRender(<ConfigPresetExportDrawer open onClose={onClose} />);
  await act(async () => {
    rendered.relayEnv.mock.resolveMostRecentOperation((operation) => MockPayloadGenerator.generate(operation, {
      Query: () => ({ configPresetExportableTypes: types }),
    }));
  });
  await screen.findByRole('button', { name: 'Export Platform Bundle' });
  return { ...rendered, onClose };
};

describe('ConfigPresetExportDrawer', () => {
  const originalLocation = window.location;

  beforeEach(() => {
    Object.defineProperty(window, 'location', { configurable: true, value: { ...originalLocation, href: '' } });
  });

  afterEach(() => {
    Object.defineProperty(window, 'location', { configurable: true, value: originalLocation });
  });

  it('shows the Platform Bundle drawer with every group and item checked by default', async () => {
    await renderOpenDrawer();
    expect(screen.getByText('Platform Bundle')).toBeInTheDocument();
    expect(screen.getByText('Select all the elements to include in your configuration bundle')).toBeInTheDocument();
    expect(screen.getByRole('checkbox', { name: 'Platform settings (2/2)' })).toHaveAttribute('data-state', 'checked');
    expect(screen.getByRole('checkbox', { name: 'Data model (1/1)' })).toHaveAttribute('data-state', 'checked');
    ['Platform configuration', 'Messages', 'Hidden entity types'].forEach((name) => {
      expect(screen.getByRole('checkbox', { name })).toHaveAttribute('data-state', 'checked');
    });
    expect(screen.getByRole('button', { name: 'Export Platform Bundle' })).toBeEnabled();
  });

  it('shows a singleton type as a single checkbox, without count, chevron or item row', async () => {
    await renderOpenDrawer();
    expect(screen.getAllByRole('checkbox')).toHaveLength(5);
    // Only the two groups can be collapsed
    expect(screen.getAllByRole('button', { name: 'Collapse' })).toHaveLength(2);
    expect(screen.queryByRole('checkbox', { name: /^Messages \(/ })).not.toBeInTheDocument();
  });

  it('updates the group count and shows a partial group as indeterminate', async () => {
    const { user } = await renderOpenDrawer();
    await user.click(screen.getByRole('checkbox', { name: 'Messages' }));
    expect(screen.getByRole('checkbox', { name: 'Messages' })).toHaveAttribute('data-state', 'unchecked');
    expect(screen.getByRole('checkbox', { name: 'Platform settings (1/2)' })).toHaveAttribute('data-state', 'indeterminate');
    expect(screen.getByRole('checkbox', { name: 'Data model (1/1)' })).toHaveAttribute('data-state', 'checked');
  });

  it('checks or unchecks every type of a group at once', async () => {
    const { user } = await renderOpenDrawer();
    await user.click(screen.getByRole('checkbox', { name: 'Platform settings (2/2)' }));
    expect(screen.getByRole('checkbox', { name: 'Platform settings (0/2)' })).toHaveAttribute('data-state', 'unchecked');
    expect(screen.getByRole('checkbox', { name: 'Platform configuration' })).toHaveAttribute('data-state', 'unchecked');
    expect(screen.getByRole('checkbox', { name: 'Messages' })).toHaveAttribute('data-state', 'unchecked');
    expect(screen.getByRole('checkbox', { name: 'Hidden entity types' })).toHaveAttribute('data-state', 'checked');

    await user.click(screen.getByRole('checkbox', { name: 'Platform settings (0/2)' }));
    expect(screen.getByRole('checkbox', { name: 'Platform settings (2/2)' })).toHaveAttribute('data-state', 'checked');
  });

  it('collapses and expands the types of a group', async () => {
    const { user } = await renderOpenDrawer();
    const [platformSettingsChevron] = screen.getAllByRole('button', { name: 'Collapse' });
    await user.click(platformSettingsChevron);
    expect(screen.queryByRole('checkbox', { name: 'Messages' })).not.toBeInTheDocument();
    expect(screen.getByRole('checkbox', { name: 'Hidden entity types' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Expand' })).toHaveAttribute('aria-expanded', 'false');

    await user.click(screen.getByRole('button', { name: 'Expand' }));
    expect(screen.getByRole('checkbox', { name: 'Messages' })).toBeInTheDocument();
  });

  it('shows a type with several items with its count, its chevron and its items, collapsed at first', async () => {
    const { user } = await renderOpenDrawer(vi.fn(), entityCatalog);
    expect(screen.getByRole('checkbox', { name: 'Platform settings (2/2)' })).toBeInTheDocument();
    expect(screen.getByRole('checkbox', { name: 'Observed data (2/2)' })).toHaveAttribute('data-state', 'checked');
    expect(screen.getAllByRole('checkbox')).toHaveLength(2);

    await user.click(screen.getByRole('button', { name: 'Expand' }));
    // Static labels are translated, user data labels are shown as is
    expect(screen.getByRole('checkbox', { name: 'Observed data' })).toBeInTheDocument();
    await user.click(screen.getByRole('checkbox', { name: 'Observed datas' }));
    expect(screen.getByRole('checkbox', { name: 'Observed data (1/2)' })).toHaveAttribute('data-state', 'indeterminate');
    expect(screen.getByRole('checkbox', { name: 'Platform settings (1/2)' })).toHaveAttribute('data-state', 'indeterminate');
  });

  it('disables the export when nothing is selected', async () => {
    const { user } = await renderOpenDrawer();
    await user.click(screen.getByRole('checkbox', { name: 'Platform settings (2/2)' }));
    await user.click(screen.getByRole('checkbox', { name: 'Data model (1/1)' }));
    expect(screen.getByRole('checkbox', { name: 'Data model (0/1)' })).toHaveAttribute('data-state', 'unchecked');
    expect(screen.getByRole('checkbox', { name: 'Hidden entity types' })).toHaveAttribute('data-state', 'unchecked');
    expect(screen.getByRole('button', { name: 'Export Platform Bundle' })).toBeDisabled();
  });

  it('closes on cancel without exporting', async () => {
    const { user, relayEnv, onClose } = await renderOpenDrawer();
    await user.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(onClose).toHaveBeenCalled();
    expect(relayEnv.mock.getAllOperations()).toHaveLength(0);
  });

  it('exports the selected items with the bundle name and downloads the stored file', async () => {
    const { user, relayEnv, onClose } = await renderOpenDrawer();
    await user.click(screen.getByRole('checkbox', { name: 'Hidden entity types' }));
    await user.type(screen.getByLabelText('Bundle name'), 'Prod preset');
    await user.click(screen.getByRole('button', { name: 'Export Platform Bundle' }));

    const operation = relayEnv.mock.getMostRecentOperation();
    expect(operation.request.variables).toEqual({
      selections: [{ type: 'platform', items: ['platform'] }, { type: 'messages', items: ['messages'] }],
      bundle_name: 'Prod preset',
    });
    await act(async () => {
      relayEnv.mock.resolve(operation, { data: { configPresetExport: { id: 'export/config_preset/opencti-config.zip' } } });
    });
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(window.location.href).toBe('/storage/get/export%2Fconfig_preset%2Fopencti-config.zip');
  });
});
