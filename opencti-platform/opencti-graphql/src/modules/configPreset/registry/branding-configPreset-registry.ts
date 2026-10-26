import { FilterMode, FilterOperator, OrderingMode, ThemeOrdering } from '../../../generated/graphql';
import { getPlatformDefaultTheme, getWhitemarkConfigPresetConfiguration } from '../../../domain/settings';
import { findAllThemes, findThemePaginated, getThemeConfigPresetConfiguration } from '../../theme/theme-domain';
import type { BasicStoreEntityTheme } from '../../theme/theme-types';
import type { ConfigPresetFamilyDefinition, ConfigPresetItemDefinition } from '../configPreset-types';
import { buildConfigPresetConnection, matchesListArgs, platformSettingsGroup } from './common-configPreset-registry';

export const BRANDING_FAMILY_ID = 'branding';

const whitemarkItem: ConfigPresetItemDefinition = {
  id: 'whitemark',
  label: 'Remove Filigran logos',
  translatable: true,
  fileName: 'whitemark.json',
  exporter: (context) => getWhitemarkConfigPresetConfiguration(context),
};
// Listed before the themes, on the first page only
const BRANDING_STATIC_ITEMS = [whitemarkItem];

// Built-in themes are listed and exported like the others, with their standard id (the same on every platform)
const themesArgs = (ids?: string[] | null, excludedIds?: string[] | null) => {
  const filters = [
    ...(ids ? [{ key: ['internal_id'], values: ids }] : []),
    ...(excludedIds && excludedIds.length > 0 ? [{ key: ['internal_id'], values: excludedIds, operator: FilterOperator.NotEq }] : []),
  ];
  return {
    orderBy: ThemeOrdering.Name,
    orderMode: OrderingMode.Asc,
    filters: filters.length > 0 ? { mode: FilterMode.And, filters, filterGroups: [] } : undefined,
  };
};

const toThemeItem = (theme: BasicStoreEntityTheme, defaultThemeId: string | undefined): ConfigPresetItemDefinition => ({
  id: theme.id,
  bundleId: theme.standard_id,
  label: theme.name,
  translatable: false,
  fileName: `${theme.standard_id}.json`,
  isDefault: theme.id === defaultThemeId,
  exporter: async () => getThemeConfigPresetConfiguration(theme),
});

// The ids of the request that can be themes: an explicit list without the static ids
const themeIds = (ids?: string[] | null) => ids?.filter((id) => !BRANDING_STATIC_ITEMS.some((item) => item.id === id));

// Branding: whitemark pinned first, then the themes, paged and searched through the theme domain
export const brandingFamily: ConfigPresetFamilyDefinition = {
  id: BRANDING_FAMILY_ID,
  label: 'Branding',
  description: 'Themes, colors, logos',
  group: platformSettingsGroup,
  directory: 'platform_settings/branding',
  listItems: async (context, user, args) => {
    const { first, after, search, ids, excludedIds } = args;
    const matchingStatics = BRANDING_STATIC_ITEMS.filter((item) => matchesListArgs(item, args));
    // The static items open the list: a cursor on a theme is after all of them, a cursor on a static item after it
    const afterStaticIndex = matchingStatics.findIndex((item) => item.id === after);
    let statics = matchingStatics;
    if (after) {
      statics = afterStaticIndex >= 0 ? matchingStatics.slice(afterStaticIndex + 1) : [];
    }
    const pageStatics = first ? statics.slice(0, first) : statics;
    const staticEdges = pageStatics.map((node) => ({ node, cursor: node.id }));
    const moreStatics = pageStatics.length < statics.length;
    const requestedThemeIds = themeIds(ids);
    // Only static ids requested: an empty filter value would match every theme
    if (requestedThemeIds?.length === 0) {
      return buildConfigPresetConnection(args, staticEdges, matchingStatics.length, moreStatics);
    }
    // The page size bounds the static items and the themes together: no room left for a theme, the next page starts with them
    const themesFirst = first ? first - pageStatics.length : first;
    const themesAfter = afterStaticIndex >= 0 ? undefined : after;
    const [page, defaultTheme] = await Promise.all([
      findThemePaginated(context, user, { first: themesFirst === 0 ? 1 : themesFirst, after: themesAfter, search, ...themesArgs(requestedThemeIds, excludedIds) }),
      getPlatformDefaultTheme(context, user),
    ]);
    const themeEdges = themesFirst === 0 ? [] : page.edges.map(({ cursor, node }) => ({ cursor, node: toThemeItem(node, defaultTheme?.id) }));
    const hasNextPage = moreStatics || (themesFirst === 0 ? page.edges.length > 0 : page.pageInfo.hasNextPage);
    return buildConfigPresetConnection(args, [...staticEdges, ...themeEdges], page.pageInfo.globalCount + matchingStatics.length, hasNextPage);
  },
  resolveItems: async (context, user, ids, excludedIds) => {
    const statics = BRANDING_STATIC_ITEMS.filter((item) => matchesListArgs(item, { ids, excludedIds }));
    const requestedThemeIds = themeIds(ids);
    if (requestedThemeIds?.length === 0) {
      return statics;
    }
    const [themes, defaultTheme] = await Promise.all([findAllThemes(context, user, themesArgs(requestedThemeIds, excludedIds)), getPlatformDefaultTheme(context, user)]);
    return [...statics, ...themes.map((theme) => toThemeItem(theme, defaultTheme?.id))];
  },
};
