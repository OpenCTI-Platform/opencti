import { describe, expect, it, vi } from 'vitest';
import { testRenderHook } from '../../../utils/tests/test-render';
import useNavSearch from './useNavSearch';
import type { NavGroup, NavSubItem } from './useNavMenu';

let subItems: NavSubItem[] = [];
vi.mock('./useNavMenu', () => ({
  default: (): NavGroup[] => [{
    id: 'settings',
    items: [{ id: 'settings', label: 'Settings', icon: null, link: '/dashboard/settings', subItems }],
  }],
}));
// Entries' own capability / feature flag checks are covered by useVisibleEntries: keep every entry here.
vi.mock('../common/menus/useVisibleEntries', () => ({ default: (entries: unknown[]) => entries }));

const search = (keyword: string) => testRenderHook(() => useNavSearch(keyword)).hook.result.current.map(({ path }) => path);

describe('Hook: useNavSearch', () => {
  const parameters = { link: '/dashboard/settings', label: 'Parameters', exact: true };
  const customization = { link: '/dashboard/settings/customization', label: 'Customization' };
  const taxonomies = { link: '/dashboard/settings/vocabularies', label: 'Taxonomies' };

  it('indexes an entry whose subsection is visible, with the subsection in the breadcrumb', () => {
    subItems = [parameters, customization];
    const { hook } = testRenderHook(() => useNavSearch('retention'));
    expect(hook.result.current).toEqual([
      { path: '/dashboard/settings/customization/retention', label: 'Retention policies', parents: ['Settings', 'Customization'] },
    ]);
  });

  it('drops an entry when its subsection is hidden, even if a broader parent is visible', () => {
    // A Customization-only user: the Taxonomies subsection (and its /vocabularies/* route) is out of reach.
    subItems = [parameters, customization];
    const customFields = '/dashboard/settings/vocabularies/custom_fields';
    expect(search('custom fields')).not.toContain(customFields);
    subItems = [parameters, customization, taxonomies];
    expect(search('custom fields')).toContain(customFields);
  });

  it('drops Import entries when the Import subsection is hidden (draft)', () => {
    subItems = [];
    expect(search('drafts')).toEqual([]);
  });
});
