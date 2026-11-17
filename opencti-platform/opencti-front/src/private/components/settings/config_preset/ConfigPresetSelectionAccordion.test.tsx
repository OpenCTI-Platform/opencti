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

  it('shows a group that holds one type of the same name as that type, not as a group with one row', async () => {
    const dashboards: ConfigPresetAccordionType = {
      key: 'dashboards',
      label: 'Dashboards',
      description: '',
      group: { key: 'dashboards', label: 'Dashboards' },
      items: [
        { key: 'workspace--1', label: 'SOC overview', translatable: false, isDefault: false, dependsOn: [] },
        { key: 'workspace--2', label: 'Executive summary', translatable: false, isDefault: false, dependsOn: [] },
      ],
      itemsPageInfo: { globalCount: 2, hasNextPage: false },
    };
    const onSelectionChange = vi.fn();
    const { user } = testRender(
      <ConfigPresetSelectionAccordion types={[themes, dashboards]} selection={{}} forced={{}} onSelectionChange={onSelectionChange} onManageType={vi.fn()} />,
    );
    // Opened as far as it opens: with a group that has the same type inside, the type would show as a second checkbox of the same name
    for (const button of screen.getAllByRole('button', { name: /^Expand Dashboards/ })) {
      await user.click(button);
    }
    expect(screen.getAllByRole('checkbox', { name: 'Dashboards (0/2)' })).toHaveLength(1);
    expect(screen.getByRole('checkbox', { name: 'SOC overview' })).toBeInTheDocument();
    // The other groups are as they were
    expect(screen.getByRole('checkbox', { name: 'Platform settings (0/40)' })).toBeInTheDocument();
    await user.click(screen.getByRole('checkbox', { name: 'Dashboards (0/2)' }));
    expect(onSelectionChange).toHaveBeenCalledWith({ dashboards: { mode: 'all', ids: [] } });
  });

  it('keeps a group that holds one type of another name, and a group that holds several types', () => {
    const labels: ConfigPresetAccordionType = {
      key: 'labels',
      label: 'Labels',
      description: '',
      group,
      items: [{ key: 'label--1', label: 'Phishing', translatable: false, isDefault: false, dependsOn: [] }],
      itemsPageInfo: { globalCount: 1, hasNextPage: false },
    };
    testRender(<ConfigPresetSelectionAccordion types={[labels]} selection={{}} forced={{}} onSelectionChange={vi.fn()} />);
    expect(screen.getByRole('checkbox', { name: 'Platform settings (0/1)' })).toBeInTheDocument();
    expandConfigPresetGroups();
    expect(screen.getByRole('checkbox', { name: 'Labels (0/1)' })).toBeInTheDocument();
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
