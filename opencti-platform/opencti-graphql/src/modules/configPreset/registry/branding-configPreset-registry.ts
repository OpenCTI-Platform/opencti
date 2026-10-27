import { FilterMode, FilterOperator, OrderingMode, ThemeOrdering } from '../../../generated/graphql';
import { getPlatformDefaultTheme, getSettings, getWhitemarkConfigPresetConfiguration, settingsEditField } from '../../../domain/settings';
import {
  addTheme,
  checkExistingTheme,
  fieldPatchTheme,
  findAllThemes,
  findById as findThemeById,
  findThemePaginated,
  getThemeConfigPresetConfiguration,
} from '../../theme/theme-domain';
import { BUILT_IN_THEME_STANDARD_IDS } from '../../theme/theme-constants';
import type { BasicStoreEntityTheme } from '../../theme/theme-types';
import type { ConfigPresetFamilyDefinition, ConfigPresetItemDefinition } from '../configPreset-types';
import type { ConfigPresetComputedItem, ConfigPresetImporter } from '../configPreset-import-types';
import { configPresetPlanKey } from '../configPreset-import-types';
import { buildImportFields, importFailureReason, isNothingToImport } from '../configPreset-import-utils';
import { THEME_STANDARD_ID_PATTERN, THEME_URL_KEYS, themeConfigurationSchema, whitemarkConfigurationSchema } from '../configPreset-import-schemas';
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

const BUILT_IN_THEME_IDS = Object.values(BUILT_IN_THEME_STANDARD_IDS);

const computeWhitemark = (item: Parameters<ConfigPresetImporter['compute']>[2]): ConfigPresetComputedItem => {
  const base = { label: WHITEMARK_LABEL, translatable: true, exists: true, fields: [] };
  const parsed = whitemarkConfigurationSchema.safeParse(item.configuration);
  if (!parsed.success) {
    return { ...base, status: 'failed', reason: importFailureReason(parsed.error) };
  }
  if (isNothingToImport(parsed.data, ['platform_whitemark'])) {
    return { ...base, status: 'skipped', reason: 'Nothing to import' };
  }
  return { ...base, status: 'overwritten' };
};

const brandingImporter: ConfigPresetImporter = {
  compute: async (context, user, item, plan): Promise<ConfigPresetComputedItem> => {
    if (item.id === WHITEMARK_ID) {
      return computeWhitemark(item);
    }
    const name = typeof item.configuration.name === 'string' ? item.configuration.name : item.id;
    const base = { label: name, translatable: false };
    // A built-in theme has the same standard id on every platform: never patched, never created
    if (BUILT_IN_THEME_IDS.includes(item.id)) {
      return { ...base, exists: true, status: 'skipped', reason: 'Built-in theme', fields: [] };
    }
    if (!THEME_STANDARD_ID_PATTERN.test(item.id) || item.configuration.standard_id !== item.id) {
      return { ...base, exists: false, status: 'failed', reason: 'The standard id of the theme does not match its id', fields: [] };
    }
    const parsed = themeConfigurationSchema.safeParse(item.configuration);
    if (!parsed.success) {
      return { ...base, exists: false, status: 'failed', reason: importFailureReason(parsed.error), fields: [] };
    }
    const fields = buildImportFields(context, parsed.data, THEME_URL_KEYS, THEME_URL_KEYS);
    const existing = await findThemeById(context, user, item.id);
    if (existing) {
      return { ...base, exists: true, status: 'overwritten', fields };
    }
    if (await checkExistingTheme(context, user, parsed.data.name)) {
      return { ...base, exists: false, status: 'failed', reason: 'Theme name already exists', fields };
    }
    plan.created.add(configPresetPlanKey(BRANDING_FAMILY_ID, item.id));
    return { ...base, exists: false, status: 'created', fields };
  },
  apply: async (context, user, item) => {
    if (item.id === WHITEMARK_ID) {
      const { platform_whitemark: whitemark } = whitemarkConfigurationSchema.parse(item.configuration);
      await settingsEditField(context, user, (await getSettings(context)).id, [{ key: 'platform_whitemark', value: [whitemark] }]);
      return undefined;
    }
    const { standard_id: standardId, ...configuration } = themeConfigurationSchema.parse(item.configuration);
    // Looked up again right before the creation: a theme with this standard id created since compute is overwritten, never duplicated
    const existing = await findThemeById(context, user, standardId);
    if (existing) {
      const input = Object.entries(configuration).filter(([, value]) => value !== null && value !== undefined).map(([key, value]) => ({ key, value: [value as string] }));
      await fieldPatchTheme(context, user, existing.id, input);
      return 'overwritten';
    }
    // addTheme trusts its input: the bundle standard id is passed, and the theme is never built-in
    await addTheme(context, user, {
      ...configuration,
      theme_logo: configuration.theme_logo ?? '',
      theme_logo_collapsed: configuration.theme_logo_collapsed ?? '',
      theme_logo_login: configuration.theme_logo_login ?? '',
      theme_login_aside_color: configuration.theme_login_aside_color ?? null,
      theme_login_aside_gradient_start: configuration.theme_login_aside_gradient_start ?? null,
      theme_login_aside_gradient_end: configuration.theme_login_aside_gradient_end ?? null,
      theme_login_aside_image: configuration.theme_login_aside_image ?? null,
      standard_id: standardId,
      built_in: false,
    });
    return undefined;
  },
};

// Branding: whitemark pinned first, then the themes, paged and searched through the theme domain
export const brandingFamily: ConfigPresetFamilyDefinition = {
  importer: brandingImporter,
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
