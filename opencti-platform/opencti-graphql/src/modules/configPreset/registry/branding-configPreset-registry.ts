import { FilterMode, FilterOperator, OrderingMode, ThemeOrdering } from '../../../generated/graphql';
import { getPlatformDefaultTheme, getSettings, getWhitemarkConfigPresetConfiguration, settingsEditField } from '../../../domain/settings';
import { FunctionalError } from '../../../config/errors';
import { ConfigImportMode } from '../../configImport/configImport-types';
import { findAllThemes, findThemePaginated, getThemeConfigPresetConfiguration } from '../../theme/theme-domain';
import { THEME_STANDARD_ID_PATTERN, THEME_URL_KEYS } from '../../theme/theme-import-schema';
import { importTheme } from '../../theme/theme-import';
import type { BasicStoreEntityTheme } from '../../theme/theme-types';
import type { ConfigPresetFamilyDefinition, ConfigPresetItemDefinition } from '../configPreset-types';
import type { ConfigPresetComputedItem, ConfigPresetImporter } from '../import/configPreset-import-types';
import { configPresetPlanKey } from '../import/configPreset-import-types';
import { buildImportFields, CONFIG_PRESET_ALREADY_EXISTS_REASON, importFailureReason, isNothingToImport } from '../import/configPreset-import-utils';
import { whitemarkConfigurationSchema } from '../import/configPreset-import-schemas';
import { buildConfigPresetConnection, matchesListArgs, platformSettingsGroup } from './common-configPreset-registry';

export const BRANDING_FAMILY_ID = 'branding';

const WHITEMARK_ID = 'whitemark';
const WHITEMARK_LABEL = 'Remove Filigran logos';

const whitemarkItem: ConfigPresetItemDefinition = {
  id: WHITEMARK_ID,
  label: WHITEMARK_LABEL,
  translatable: true,
  fileName: 'whitemark.json',
  // The switch of the whitemark is disabled on a Community platform: the import does not set it either
  requiresEnterpriseEdition: true,
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

const computeWhitemark = (item: Parameters<ConfigPresetImporter['compute']>[2], mode: ConfigImportMode): ConfigPresetComputedItem => {
  const base = { label: WHITEMARK_LABEL, translatable: true, exists: true, fields: [] };
  const parsed = whitemarkConfigurationSchema.safeParse(item.configuration);
  if (!parsed.success) {
    return { ...base, status: 'failed', reason: importFailureReason(parsed.error) };
  }
  // A setting has no copy: it is left as it is
  if (mode === ConfigImportMode.Copy) {
    return { ...base, status: 'skipped', reason: CONFIG_PRESET_ALREADY_EXISTS_REASON };
  }
  if (isNothingToImport(parsed.data, ['platform_whitemark'])) {
    return { ...base, status: 'skipped', reason: 'Nothing to import' };
  }
  return { ...base, status: 'overwritten' };
};

const brandingImporter: ConfigPresetImporter = {
  compute: async (context, user, item, plan, mode): Promise<ConfigPresetComputedItem> => {
    if (item.id === WHITEMARK_ID) {
      return computeWhitemark(item, mode);
    }
    const name = typeof item.configuration.name === 'string' ? item.configuration.name : item.id;
    const base = { label: name, translatable: false };
    // The bundle id of a theme is its standard id
    if (!THEME_STANDARD_ID_PATTERN.test(item.id) || item.configuration.standard_id !== item.id) {
      return { ...base, exists: false, status: 'failed', reason: 'The standard id of the theme does not match its id', fields: [] };
    }
    // The rules of a theme are the ones of the theme module: a dry run decides what the import would do
    const result = await importTheme(context, user, item.configuration, { mode, dryRun: true });
    // The theme the items depend on is the one with this standard id: a copy of a theme that exists is another theme
    if (result.status === 'created' && !result.exists) {
      plan.created.add(configPresetPlanKey(BRANDING_FAMILY_ID, item.id));
    }
    // The preview shows the URLs and the images of a theme that is valid
    const fields = result.configuration ? buildImportFields(result.configuration, THEME_URL_KEYS) : [];
    return { ...base, exists: result.exists, status: result.status, reason: result.reason, fields };
  },
  apply: async (context, user, item, computed, mode) => {
    if (item.id === WHITEMARK_ID) {
      const { platform_whitemark: whitemark } = whitemarkConfigurationSchema.parse(item.configuration);
      await settingsEditField(context, user, (await getSettings(context)).id, [{ key: 'platform_whitemark', value: [whitemark] }]);
      return undefined;
    }
    // Decided again by the theme module as it writes: a theme with this standard id created since compute is overwritten, never duplicated
    const result = await importTheme(context, user, item.configuration, { mode });
    if (result.status !== 'created' && result.status !== 'overwritten') {
      throw FunctionalError(result.reason ?? 'Theme cannot be imported');
    }
    return result.status === computed.status ? undefined : result.status;
  },
};

// Branding: whitemark pinned first, then the themes, paged and searched through the theme domain
export const brandingFamily: ConfigPresetFamilyDefinition = {
  importer: brandingImporter,
  // The themes that exist can be overwritten or copied
  importModes: [ConfigImportMode.Overwrite, ConfigImportMode.Copy],
  staticItems: BRANDING_STATIC_ITEMS,
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
