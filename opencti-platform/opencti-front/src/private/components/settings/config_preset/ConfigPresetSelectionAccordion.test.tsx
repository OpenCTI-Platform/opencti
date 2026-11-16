import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import ConfigPresetSelectionAccordion, { type ConfigPresetAccordionType } from './ConfigPresetSelectionAccordion';
import { expandConfigPresetGroups } from '../../../../utils/tests/config-preset-test-utils';

const group = { key: 'platformSettings', label: 'Platform settings' };
// More themes than the first page holds: the type is managed in a sub-view
const themes: ConfigPresetAccordionType = {
  key: 'branding',
  label: 'Branding',
  description: 'Themes',
  group,
  items: [
    { key: 'theme--1', label: 'Dark', translatable: false, isDefault: true, dependsOn: [] },
    { key: 'theme--2', label: 'Light', translatable: false, isDefault: false, dependsOn: [] },
  ],
  itemsPageInfo: { globalCount: 40, hasNextPage: true },
};

describe('ConfigPresetSelectionAccordion', () => {
  it('selects or unselects a type that is managed in a sub-view, and opens the sub-view', async () => {
    const onSelectionChange = vi.fn();
    const onManageType = vi.fn();
    const { user } = testRender(
      <ConfigPresetSelectionAccordion types={[themes]} selection={{}} forced={{}} onSelectionChange={onSelectionChange} onManageType={onManageType} />,
    );
    expandConfigPresetGroups();
    await user.click(screen.getByRole('checkbox', { name: 'Branding (0/40)' }));
    expect(onSelectionChange).toHaveBeenCalledWith({ branding: { mode: 'all', ids: [] } });
    await user.click(screen.getByRole('button', { name: 'Manage' }));
    expect(onManageType).toHaveBeenCalledWith('branding');
  });

  it('unselects a type that was selected', async () => {
    const onSelectionChange = vi.fn();
    const { user } = testRender(
      <ConfigPresetSelectionAccordion
        types={[themes]}
        selection={{ branding: { mode: 'all', ids: [] } }}
        forced={{}}
        onSelectionChange={onSelectionChange}
        onManageType={vi.fn()}
      />,
    );
    expandConfigPresetGroups();
    await user.click(screen.getByRole('checkbox', { name: 'Branding (40/40)' }));
    expect(onSelectionChange).toHaveBeenCalledWith({ branding: { mode: 'some', ids: [] } });
  });

  it('shows a singleton that has no description as its label alone', () => {
    const type: ConfigPresetAccordionType = {
      key: 'whitemark',
      label: 'Remove Filigran logos',
      description: '',
      group,
      items: [{ key: 'whitemark', label: 'Remove Filigran logos', translatable: true, isDefault: false, dependsOn: [] }],
      itemsPageInfo: { globalCount: 1 },
    };
    testRender(<ConfigPresetSelectionAccordion types={[type]} selection={{}} forced={{}} onSelectionChange={vi.fn()} />);
    expandConfigPresetGroups();
    expect(screen.getByRole('checkbox', { name: 'Remove Filigran logos' })).toBeInTheDocument();
  });

  it('starts with its groups collapsed, and shows their types once opened', async () => {
    const { user } = testRender(
      <ConfigPresetSelectionAccordion types={[themes]} selection={{}} forced={{}} onSelectionChange={vi.fn()} onManageType={vi.fn()} />,
    );
    expect(screen.getByRole('checkbox', { name: 'Platform settings (0/40)' })).toBeInTheDocument();
    expect(screen.queryByRole('checkbox', { name: 'Branding (0/40)' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Expand Platform settings (0/40)' }));
    expect(screen.getByRole('checkbox', { name: 'Branding (0/40)' })).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Collapse Platform settings (0/40)' }));
    expect(screen.queryByRole('checkbox', { name: 'Branding (0/40)' })).not.toBeInTheDocument();
  });
});
