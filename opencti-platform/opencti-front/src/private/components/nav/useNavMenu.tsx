import { ArchitectureOutlined } from '@mui/icons-material';
import React from 'react';
import { useFormatter } from '../../../components/i18n';
import useAuth from '../../../utils/hooks/useAuth';
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
  /** Extra words matching this entry in the main pages search (in the user language and in English). */
  keywords?: string[];
  /** Label in English (the translation key), always searchable whatever the user language. */
  englishLabel?: string;
}

export interface NavItem {
  id: string;
  label: string;
  icon: React.ReactNode;
  link: string;
  exact?: boolean;
  subItems?: NavSubItem[];
  /** Top-level page only (no sub-items): its extra words in the main pages search (in the user language and in English). */
  keywords?: string[];
  /** Label in English (the translation key), always searchable whatever the user language. */
  englishLabel?: string;
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
  const visibleEntries = useVisibleEntries(allMenuEntries);
  const isVisible = (entry: MenuEntry) => visibleEntries.includes(entry);

  const pageItem = (entry: MenuEntry): NavSubItem => ({
    link: entry.path,
    label: t_i18n(entry.label),
    englishLabel: entry.label,
    icon: entry.icon,
    exact: entry.exact,
    // Translation keys are the English texts: the search matches both languages.
    keywords: entry.keywords?.flatMap((keyword) => [t_i18n(keyword), keyword]),
    granted: isVisible(entry),
  });
  const subItem = (item: NavSectionItem): NavSubItem => {
    if ('path' in item) return pageItem(item);
    const firstVisible = item.entries.find(isVisible);
    return {
      link: (firstVisible ?? item.entries[0]).path,
      label: t_i18n(item.label),
      englishLabel: item.label,
      paths: item.entries.map(({ path }) => path),
      granted: !!firstVisible,
    };
  };

  const buildItem = (section: NavSection): RawNavGroup['items'][number] => {
    if ('page' in section) {
      const { link, label, englishLabel, icon, exact, granted, keywords } = pageItem(section.page);
      return granted && { id: section.id, label, englishLabel, icon, link, exact, keywords };
    }
    const subItems = section.items.map(subItem);
    const firstVisible = subItems.find((sub) => sub.granted);
    return firstVisible && {
      id: section.id,
      label: t_i18n(section.label),
      englishLabel: section.label,
      icon: section.icon,
      link: firstVisible.link,
      subItems,
    };
  };

  // Its link is built from the current draft, and it only exists in draft: not expressible as a page entry.
  const draftOverview = draftContext && {
    id: 'draft-overview',
    label: t_i18n('Draft overview'),
    englishLabel: 'Draft overview',
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
