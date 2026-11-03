import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import ConfigPresetSelectionAccordion, { type ConfigPresetAccordionType } from './ConfigPresetSelectionAccordion';

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
    await user.click(screen.getByRole('checkbox', { name: 'Branding (40/40)' }));
    expect(onSelectionChange).toHaveBeenCalledWith({ branding: { mode: 'some', ids: [] } });
  });
});
