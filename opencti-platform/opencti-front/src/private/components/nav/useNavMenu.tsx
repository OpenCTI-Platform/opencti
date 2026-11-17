import { ArchitectureOutlined } from '@mui/icons-material';
import React from 'react';
import { useFormatter } from '../../../components/i18n';
import useAuth from '../../../utils/hooks/useAuth';
import { useHiddenEntities } from '../../../utils/hooks/useEntitySettings';
import useHelper from '../../../utils/hooks/useHelper';
import type { MenuEntry, NavSection, NavSectionItem } from '../common/menus/menuEntry';
import useVisibleEntries from '../common/menus/useVisibleEntries';
import { allMenuEntries } from './menuEntries';
import { navSections } from './navSections';

export interface NavSubItem {
  link: string;
  label: string;
  /** Row standing for several pages (a sub-section): the paths it covers, for its selected state and the search. */
  paths?: string[];
  icon?: React.ReactNode;
  exact?: boolean;
  granted?: boolean;
  /** Extra words matching this entry in the main pages search. */
  keywords?: string[];
}

export interface NavItem {
  id: string;
  label: string;
  icon: React.ReactNode;
  link: string;
  exact?: boolean;
  subItems?: NavSubItem[];
  /** Top-level page only (no sub-items): its extra words in the main pages search. */
  keywords?: string[];
}

export interface NavGroup {
  id: string;
  items: NavItem[];
}

export interface RawNavGroup {
  id: string;
  items: (NavItem | false | null | undefined)[];
}

// Generic builder: the structure comes from `navSections` and the access rules (capabilities, feature flag, EE, draft)
// from the `*.entries.ts(x)` files, so nothing about a page is restated here.
const useNavMenu = (): NavGroup[] => {
  const { t_i18n } = useFormatter();
  const { me: { draftContext } } = useAuth();
  const { isTrashEnable } = useHelper();
  const hiddenEntities = useHiddenEntities();
  const visibleEntries = useVisibleEntries(allMenuEntries);

  // Pages switched off by the platform settings rather than by their entry: hidden entity types (matched on the
  // entry's own type, not on a shared URL: several types, e.g. every observable, resolve to one page), disabled trash.
  const isVisible = (entry: MenuEntry) => visibleEntries.includes(entry)
    && !(entry.entityType && hiddenEntities.includes(entry.entityType))
    && !(entry.path === '/dashboard/trash' && !isTrashEnable());

  const pageItem = (entry: MenuEntry): NavSubItem => ({
    link: entry.path,
    label: t_i18n(entry.label),
    icon: entry.icon,
    exact: entry.exact,
    keywords: entry.keywords?.map((keyword) => t_i18n(keyword)),
    granted: isVisible(entry),
  });
  const subItem = (item: NavSectionItem): NavSubItem => {
    if ('path' in item) return pageItem(item);
    const firstVisible = item.entries.find(isVisible);
    return {
      link: (firstVisible ?? item.entries[0]).path,
      label: t_i18n(item.label),
      paths: item.entries.map(({ path }) => path),
      granted: !!firstVisible,
    };
  };

  const buildItem = (section: NavSection): RawNavGroup['items'][number] => {
    if ('page' in section) {
      const { link, label, icon, exact, granted, keywords } = pageItem(section.page);
      return granted && { id: section.id, label, icon, link, exact, keywords };
    }
    const subItems = section.items.map(subItem);
    const firstVisible = subItems.find((sub) => sub.granted);
    return firstVisible && {
      id: section.id,
      label: t_i18n(section.label),
      icon: section.icon,
      link: firstVisible.link,
      subItems,
    };
  };

  // Its link is built from the current draft, and it only exists in draft: not expressible as a page entry.
  const draftOverview = draftContext && {
    id: 'draft-overview',
    label: t_i18n('Draft overview'),
    icon: <ArchitectureOutlined />,
    link: `/dashboard/data/import/draft/${draftContext.id}`,
  };

  const groups = new Map<string, RawNavGroup['items']>([['main', [draftOverview]]]);
  navSections.forEach((section) => groups.set(section.group, [...(groups.get(section.group) ?? []), buildItem(section)]));
  return filterNavGroups([...groups].map(([id, items]) => ({ id, items })));
};

export const filterNavGroups = (groups: (RawNavGroup | false)[]): NavGroup[] => groups
  .filter((group): group is RawNavGroup => !!group)
  .map((group) => ({
    ...group,
    items: group.items
      .filter((item): item is NavItem => !!item)
      .map((item) => (item.subItems ? { ...item, subItems: item.subItems.filter((sub) => sub.granted !== false) } : item)),
  }))
  .filter((group) => group.items.length > 0);

export default useNavMenu;
