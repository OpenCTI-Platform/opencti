import React, { useSyncExternalStore } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, screen, waitFor, within } from '@testing-library/react';
import { MockPayloadGenerator } from 'relay-test-utils';
import testRender, { createMockUserContext } from '../../../../../utils/tests/test-render';
import ConfigPresetExportDrawer from './ConfigPresetExportDrawer';

// The Enterprise Edition of the platform, which can change while the drawer is open (a license activated from it)
const enterpriseEdition = vi.hoisted(() => {
  const listeners = new Set<() => void>();
  return {
    enabled: false,
    subscribe: (listener: () => void) => {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
    activate: () => {
      enterpriseEdition.enabled = true;
      listeners.forEach((listener) => listener());
    },
  };
});
vi.mock('../../../../../utils/hooks/useEnterpriseEdition', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../utils/hooks/useEnterpriseEdition')>()),
  default: () => useSyncExternalStore(enterpriseEdition.subscribe, () => enterpriseEdition.enabled),
}));

const platformSettings = { key: 'platformSettings', label: 'Platform settings' };
const item = (key: string, label: string, overrides: Record<string, unknown> = {}) => ({
  key,
  label,
  translatable: true,
  isDefault: false,
  dependsOn: [],
  ...overrides,
});
const type = (key: string, label: string, items: ReturnType<typeof item>[], overrides: Record<string, unknown> = {}) => ({
  key,
  label,
  description: `${label} description`,
  group: platformSettings,
  requiresEnterpriseEdition: false,
  items,
  itemsPageInfo: { hasNextPage: false, globalCount: items.length },
  ...overrides,
});
const singleton = (key: string, label: string, overrides: Record<string, unknown> = {}) => type(key, label, [item(key, label)], overrides);
const catalog = [
  singleton('platform', 'Platform configuration'),
  singleton('messages', 'Messages'),
  singleton('hiddenEntityTypes', 'Hidden entity types', { group: { key: 'dataModel', label: 'Data model' } }),
];

// A type with several items: 'Observed datas' is an i18n key translated to 'Observed data'
const entityCatalog = [type('observedData', 'Observed datas', [
  item('static', 'Observed datas'),
  item('entity', 'Observed datas', { translatable: false }),
])];

// Branding: the themes, the built-in ones are not exported. The platform configuration depends on the custom default theme.
const themeItems = [
  item('theme-acme', 'ACME', { translatable: false }),
  item('theme-night', 'Night shift', { translatable: false }),
  item('theme-soc', 'SOC night', { translatable: false, isDefault: true }),
];
const platformType = (dependsOn: unknown[]) => type('platform', 'Platform configuration', [item('platform', 'Platform configuration', { dependsOn })], {
  description: 'Title, favicon, default theme, language',
});
const messagesType = type('messages', 'Messages', [item('banner', 'Banner'), item('login', 'Login message')]);
const tableCatalog = (brandingOverrides: Record<string, unknown> = {}) => [
  platformType([{ type: 'branding', key: 'theme-soc' }]),
  type('branding', 'Branding', themeItems, brandingOverrides),
  messagesType,
];
// The default theme is built-in, so it is not listed: the platform configuration has no dependency
const builtInDefaultCatalog = () => [
  platformType([]),
  type('branding', 'Branding', [item('theme-acme', 'ACME', { translatable: false }), item('theme-night', 'Night shift', { translatable: false })]),
];
// More themes than the first page
const pagedBrandingCatalog = () => tableCatalog({ itemsPageInfo: { hasNextPage: true, globalCount: 30 } });

// The export is for BYPASS users
const userContext = createMockUserContext({
  me: { name: 'admin', capabilities: [{ name: 'BYPASS' }], userSubscriptions: { edges: [] } },
});
const renderOpenDrawer = async (onClose = vi.fn(), types: unknown[] = catalog) => {
  const rendered = testRender(<ConfigPresetExportDrawer open onClose={onClose} />, { userContext });
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
    enterpriseEdition.enabled = false;
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
    expect(screen.getAllByRole('button', { name: /^Collapse/ })).toHaveLength(2);
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
    const [platformSettingsChevron] = screen.getAllByRole('button', { name: /^Collapse/ });
    await user.click(platformSettingsChevron);
    expect(screen.queryByRole('checkbox', { name: 'Messages' })).not.toBeInTheDocument();
    expect(screen.getByRole('checkbox', { name: 'Hidden entity types' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^Expand/ })).toHaveAttribute('aria-expanded', 'false');

    await user.click(screen.getByRole('button', { name: /^Expand/ }));
    expect(screen.getByRole('checkbox', { name: 'Messages' })).toBeInTheDocument();
  });

  it('shows a type with several items with its count, its chevron and its items, collapsed at first', async () => {
    const { user } = await renderOpenDrawer(vi.fn(), entityCatalog);
    expect(screen.getByRole('checkbox', { name: 'Platform settings (2/2)' })).toBeInTheDocument();
    expect(screen.getByRole('checkbox', { name: 'Observed data (2/2)' })).toHaveAttribute('data-state', 'checked');
    expect(screen.getAllByRole('checkbox')).toHaveLength(2);
    expect(screen.queryByRole('button', { name: 'Manage' })).not.toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: /^Expand/ }));
    // Static labels are translated, user data labels are shown as is
    expect(screen.getByRole('checkbox', { name: 'Observed data' })).toBeInTheDocument();
    await user.click(screen.getByRole('checkbox', { name: 'Observed datas' }));
    expect(screen.getByRole('checkbox', { name: 'Observed data (1/2)' })).toHaveAttribute('data-state', 'indeterminate');
    expect(screen.getByRole('checkbox', { name: 'Platform settings (1/2)' })).toHaveAttribute('data-state', 'indeterminate');
  });

  it('does not show a type without item, nor a group left without type', async () => {
    const emptyTypes = [
      ...catalog,
      { key: 'observedData', label: 'Observed datas', group: { key: 'entities', label: 'Entities' }, requiresEnterpriseEdition: false, items: [] },
    ];
    await renderOpenDrawer(vi.fn(), emptyTypes);
    expect(screen.getByRole('checkbox', { name: 'Platform settings (2/2)' })).toBeInTheDocument();
    expect(screen.queryByRole('checkbox', { name: /Entities/ })).not.toBeInTheDocument();
    expect(screen.queryByRole('checkbox', { name: /Observed data/ })).not.toBeInTheDocument();
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

  it('stays open with its selection when the export fails', async () => {
    const { user, relayEnv, onClose } = await renderOpenDrawer();
    await user.click(screen.getByRole('checkbox', { name: 'Messages' }));
    await user.click(screen.getByRole('button', { name: 'Export Platform Bundle' }));
    await act(async () => {
      relayEnv.mock.rejectMostRecentOperation(new Error('Export failed'));
    });

    expect(onClose).not.toHaveBeenCalled();
    expect(window.location.href).toBe('');
    expect(screen.getByRole('checkbox', { name: 'Messages' })).toHaveAttribute('data-state', 'unchecked');
    expect(screen.getByRole('checkbox', { name: 'Platform settings (1/2)' })).toHaveAttribute('data-state', 'indeterminate');
    expect(screen.getByRole('button', { name: 'Export Platform Bundle' })).toBeEnabled();
  });

  it('exports the selected items with the bundle name and downloads the stored file', async () => {
    const { user, relayEnv, onClose } = await renderOpenDrawer();
    await user.click(screen.getByRole('checkbox', { name: 'Hidden entity types' }));
    await user.type(screen.getByLabelText('Bundle name'), 'Prod preset');
    await user.click(screen.getByRole('button', { name: 'Export Platform Bundle' }));

    const operation = relayEnv.mock.getMostRecentOperation();
    expect(operation.request.variables).toEqual({
      selections: [{ type: 'platform', items: null }, { type: 'messages', items: null }],
      bundle_name: 'Prod preset',
    });
    await act(async () => {
      relayEnv.mock.resolve(operation, { data: { configPresetExport: { id: 'export/config_preset/opencti-config.zip' } } });
    });
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(window.location.href).toBe('/storage/get/export%2Fconfig_preset%2Fopencti-config.zip');
  });

  describe('a type that needs the Enterprise Edition', () => {
    // On a platform without it the type has no item; with it, one
    const lockedType = () => type('whitemark', 'Remove Filigran logos', [], { requiresEnterpriseEdition: true });
    const unlockedType = () => type('whitemark', 'Remove Filigran logos', [item('whitemark', 'Remove Filigran logos')], { requiresEnterpriseEdition: true });
    const GATE = 'Activate the Enterprise Edition to export this item';
    const exportedTypes = async ({ user, relayEnv }: Awaited<ReturnType<typeof renderOpenDrawer>>) => {
      await user.click(screen.getByRole('button', { name: 'Export Platform Bundle' }));
      return (relayEnv.mock.getMostRecentOperation().request.variables.selections as { type: string }[]).map(({ type: key }) => key);
    };

    it('is shown locked on a platform without it, with its chip, and is not exported', async () => {
      const rendered = await renderOpenDrawer(vi.fn(), [...catalog, lockedType()]);
      const gate = screen.getByRole('button', { name: GATE });
      expect(within(gate).getByRole('checkbox', { hidden: true })).toHaveAttribute('data-state', 'unchecked');
      expect(within(gate).getByText('EE')).toBeInTheDocument();
      expect(within(gate).getByText('Remove Filigran logos description')).toBeInTheDocument();
      // It has nothing to count: the groups are as without it
      expect(screen.getByRole('checkbox', { name: 'Platform settings (2/2)' })).toHaveAttribute('data-state', 'checked');
      expect(await exportedTypes(rendered)).toEqual(['platform', 'messages', 'hiddenEntityTypes']);
    });

    it('is not selected by the group, which can still be cleared and checked', async () => {
      const rendered = await renderOpenDrawer(vi.fn(), [...catalog, lockedType()]);
      await rendered.user.click(screen.getByRole('checkbox', { name: 'Platform settings (2/2)' }));
      expect(screen.getByRole('checkbox', { name: 'Platform settings (0/2)' })).toHaveAttribute('data-state', 'unchecked');
      await rendered.user.click(screen.getByRole('checkbox', { name: 'Platform settings (0/2)' }));
      expect(screen.getByRole('checkbox', { name: 'Platform settings (2/2)' })).toHaveAttribute('data-state', 'checked');
      expect(within(screen.getByRole('button', { name: GATE })).getByRole('checkbox', { hidden: true })).toHaveAttribute('data-state', 'unchecked');
    });

    it('opens the license dialog instead of being selected', async () => {
      const { user } = await renderOpenDrawer(vi.fn(), [...catalog, lockedType()]);
      await user.click(screen.getByRole('button', { name: GATE }));
      expect(await screen.findByText('OpenCTI Enterprise Edition (EE) license agreement')).toBeInTheDocument();
    });

    it('is loaded with its items once a license is activated, and exported, without losing the selection made until then', async () => {
      const rendered = await renderOpenDrawer(vi.fn(), [...catalog, lockedType()]);
      await rendered.user.click(screen.getByRole('checkbox', { name: 'Messages' }));
      await act(async () => {
        enterpriseEdition.activate();
      });
      // The catalog is read again, with what the license adds
      await act(async () => {
        rendered.relayEnv.mock.resolveMostRecentOperation((operation) => MockPayloadGenerator.generate(operation, {
          Query: () => ({ configPresetExportableTypes: [...catalog, unlockedType()] }),
        }));
      });
      expect(await screen.findByRole('checkbox', { name: 'Remove Filigran logos' })).toHaveAttribute('data-state', 'checked');
      expect(screen.queryByRole('button', { name: GATE })).not.toBeInTheDocument();
      expect(screen.getByRole('checkbox', { name: 'Messages' })).toHaveAttribute('data-state', 'unchecked');
      expect(await exportedTypes(rendered)).toEqual(['platform', 'hiddenEntityTypes', 'whitemark']);
    });
  });

  it('shows the description of each category under its name', async () => {
    await renderOpenDrawer(vi.fn(), tableCatalog());
    expect(screen.getByText('Title, favicon, default theme, language')).toBeInTheDocument();
    expect(screen.getByText('Branding description')).toBeInTheDocument();
    expect(screen.getByText('Messages description')).toBeInTheDocument();
  });

  it('lists the items of a small type inline, forced dependencies checked and disabled', async () => {
    const { user } = await renderOpenDrawer(vi.fn(), tableCatalog());
    expect(screen.getByRole('checkbox', { name: 'Platform settings (6/6)' })).toBeInTheDocument();
    // Branding and messages are categories with several items
    for (const chevron of screen.getAllByRole('button', { name: /^Expand/ })) {
      await user.click(chevron);
    }
    const brandingRows = ['ACME', 'Night shift', 'SOC night'].map((name) => screen.getByRole('checkbox', { name }));
    brandingRows.slice(1).forEach((row, index) => expect(brandingRows[index].compareDocumentPosition(row) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy());
    expect(screen.getByRole('checkbox', { name: 'Branding (3/3)' })).toHaveAttribute('data-state', 'checked');
    // A theme can be unticked
    expect(screen.getByRole('checkbox', { name: 'Night shift' })).toBeEnabled();
    await user.click(screen.getByRole('checkbox', { name: 'Night shift' }));
    expect(screen.getByRole('checkbox', { name: 'Branding (2/3)' })).toHaveAttribute('data-state', 'indeterminate');
    // The custom default theme is a dependency of the platform configuration
    expect(screen.getByRole('checkbox', { name: 'SOC night' })).toHaveAttribute('data-state', 'checked');
    expect(screen.getByRole('checkbox', { name: 'SOC night' })).toBeDisabled();
    expect(screen.getByText('default')).toBeInTheDocument();
    // Unchecking the branding keeps the forced theme
    await user.click(screen.getByRole('checkbox', { name: 'Branding (2/3)' }));
    await user.click(screen.getByRole('checkbox', { name: 'Branding (3/3)' }));
    expect(screen.getByRole('checkbox', { name: 'Branding (1/3)' })).toHaveAttribute('data-state', 'indeterminate');
    expect(screen.getByRole('checkbox', { name: 'ACME' })).toHaveAttribute('data-state', 'unchecked');
    // Without the platform configuration nothing is forced
    await user.click(screen.getByRole('checkbox', { name: 'Platform configuration' }));
    expect(screen.getByRole('checkbox', { name: 'SOC night' })).toBeEnabled();
    expect(screen.getByRole('checkbox', { name: 'Branding (0/3)' })).toHaveAttribute('data-state', 'unchecked');
  });

  it('forces nothing when the default theme is built-in, which is not listed', async () => {
    const { user } = await renderOpenDrawer(vi.fn(), builtInDefaultCatalog());
    await user.click(screen.getByRole('button', { name: /^Expand/ }));
    expect(screen.queryByText('default')).not.toBeInTheDocument();
    expect(screen.getByRole('checkbox', { name: 'ACME' })).toBeEnabled();
    await user.click(screen.getByRole('checkbox', { name: 'ACME' }));
    expect(screen.getByRole('checkbox', { name: 'Branding (1/2)' })).toHaveAttribute('data-state', 'indeterminate');
  });

  describe('sub-view of a type with more items than its first page', () => {
    let intersect: (() => void) | undefined;

    beforeEach(() => {
      intersect = undefined;
      vi.stubGlobal('IntersectionObserver', class {
        constructor(callback: (entries: { isIntersecting: boolean }[]) => void) {
          intersect = () => callback([{ isIntersecting: true }]);
        }

        observe() {}

        disconnect() {}
      });
    });

    afterEach(() => {
      vi.unstubAllGlobals();
    });

    const resolveItems = async (relayEnv: Awaited<ReturnType<typeof renderOpenDrawer>>['relayEnv'], nodes: unknown[], hasNextPage = false) => {
      await act(async () => {
        relayEnv.mock.resolveMostRecentOperation((operation) => MockPayloadGenerator.generate(operation, {
          Query: () => ({
            configPresetExportableItems: {
              edges: nodes.map((node) => ({ node, cursor: (node as { key: string }).key })),
              pageInfo: { hasNextPage, endCursor: 'next', globalCount: 30 },
            },
          }),
        }));
      });
    };

    const openThemes = async () => {
      const rendered = await renderOpenDrawer(vi.fn(), pagedBrandingCatalog());
      await rendered.user.click(screen.getByRole('button', { name: 'Manage' }));
      await resolveItems(rendered.relayEnv, themeItems, true);
      return rendered;
    };

    it('shows Manage instead of the items, then opens the sub-view with every theme as rows', async () => {
      const { relayEnv } = await openThemes();
      expect(screen.queryByRole('button', { name: 'Export Platform Bundle' })).not.toBeInTheDocument();
      expect(screen.getByText('30 / 30 selected')).toBeInTheDocument();
      expect(screen.getByRole('checkbox', { name: 'Night shift' })).toBeEnabled();
      expect(screen.getByRole('checkbox', { name: 'ACME' })).toHaveAttribute('data-state', 'checked');
      expect(screen.getByText('All 30 selected')).toBeInTheDocument();
      // Infinite scroll
      act(() => intersect?.());
      expect(relayEnv.mock.getMostRecentOperation().request.variables).toMatchObject({ type: 'branding', cursor: 'next', count: 25 });
    });

    it('goes back to the bundle with the arrow or the button, keeping the selection', async () => {
      const { user } = await openThemes();
      await user.click(screen.getByRole('checkbox', { name: 'ACME' }));
      expect(screen.getByText('29 / 30 selected')).toBeInTheDocument();
      expect(screen.getByText('29 selected, 1 excluded')).toBeInTheDocument();
      await user.click(screen.getByRole('button', { name: 'Back' }));
      expect(screen.getByRole('checkbox', { name: 'Branding (29/30)' })).toHaveAttribute('data-state', 'indeterminate');
      await user.click(screen.getByRole('button', { name: 'Manage' }));
      await user.click(screen.getByRole('button', { name: 'Back to bundle' }));
      expect(screen.getByRole('button', { name: 'Export Platform Bundle' })).toBeInTheDocument();
    });

    it('queries the excluded or selected items, and searches from the first page', async () => {
      const { user, relayEnv } = await openThemes();
      await user.click(screen.getByRole('checkbox', { name: 'ACME' }));
      await user.click(screen.getByRole('button', { name: 'Excluded 1' }));
      expect(relayEnv.mock.getMostRecentOperation().request.variables).toMatchObject({ type: 'branding', ids: ['theme-acme'], search: '' });
      await resolveItems(relayEnv, [themeItems[0]]);
      await user.click(screen.getByRole('button', { name: 'Selected 29' }));
      expect(relayEnv.mock.getMostRecentOperation().request.variables).toMatchObject({ excludedIds: ['theme-acme'] });
      await resolveItems(relayEnv, [themeItems[1]]);
      await user.type(screen.getByRole('searchbox', { name: 'Search' }), 'soc');
      await waitFor(() => expect(relayEnv.mock.getMostRecentOperation().request.variables).toMatchObject({ search: 'soc', excludedIds: ['theme-acme'] }));
      expect(relayEnv.mock.getMostRecentOperation().request.variables).not.toHaveProperty('cursor', 'next');
    });

    it('applies a filter chosen while a search is waiting with that search, and the search does not undo it', async () => {
      const { user, relayEnv } = await openThemes();
      await user.click(screen.getByRole('checkbox', { name: 'ACME' }));
      await user.type(screen.getByRole('searchbox', { name: 'Search' }), 'soc');
      await user.click(screen.getByRole('button', { name: 'Excluded 1' }));
      expect(relayEnv.mock.getMostRecentOperation().request.variables).toMatchObject({ search: 'soc', ids: ['theme-acme'] });
      // Past the delay of the search: the filter is still the chosen one
      await new Promise((resolve) => {
        setTimeout(resolve, 400);
      });
      expect(relayEnv.mock.getMostRecentOperation().request.variables).toMatchObject({ search: 'soc', ids: ['theme-acme'] });
    });

    it('clears the selection of the type', async () => {
      const { user } = await openThemes();
      await user.click(screen.getByRole('button', { name: 'Clear selection' }));
      // The default theme stays: the platform configuration depends on it
      expect(screen.getByText('1 / 30 selected')).toBeInTheDocument();
      expect(screen.getByRole('checkbox', { name: 'ACME' })).toHaveAttribute('data-state', 'unchecked');
    });

    it('exports every theme but the excluded ones', async () => {
      const { user, relayEnv } = await openThemes();
      await user.click(screen.getByRole('checkbox', { name: 'ACME' }));
      await user.click(screen.getByRole('button', { name: 'Back to bundle' }));
      await user.click(screen.getByRole('button', { name: 'Export Platform Bundle' }));
      expect(relayEnv.mock.getMostRecentOperation().request.variables.selections).toEqual([
        { type: 'platform', items: null },
        { type: 'branding', items: null, excluded_items: ['theme-acme'] },
        { type: 'messages', items: null },
      ]);
    });
  });
});
