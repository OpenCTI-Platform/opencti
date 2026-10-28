import { FilterMode, FilterOperator, OrderingMode, ThemeOrdering } from '../../../generated/graphql';
import { getPlatformDefaultTheme } from '../../../domain/settings';
import { FunctionalError } from '../../../config/errors';
import { ConfigImportMode } from '../../configImport/configImport-types';
import { findAllThemes, findThemePaginated } from '../../theme/theme-domain';
import { getThemeConfigPresetConfiguration } from '../../theme/theme-export';
import { THEME_STANDARD_ID_PATTERN, THEME_URL_KEYS } from '../../theme/theme-import-schema';
import { importTheme } from '../../theme/theme-import';
import type { BasicStoreEntityTheme } from '../../theme/theme-types';
import type { ConfigPresetFamilyDefinition, ConfigPresetItemDefinition } from '../configPreset-types';
import type { ConfigPresetComputedItem, ConfigPresetImporter } from '../import/configPreset-import-types';
import { configPresetPlanKey } from '../import/configPreset-import-types';
import { buildImportFields } from '../import/configPreset-import-utils';
import { buildConfigPresetConnection, platformSettingsGroup } from './common-configPreset-registry';

export const BRANDING_FAMILY_ID = 'branding';

// Built-in themes are neither listed nor exported: they are the same on every platform, and an import never writes them.
// A built-in default theme is still referenced by the platform item, by its standard id.
const themesArgs = (ids?: string[] | null, excludedIds?: string[] | null) => {
  const filters = [
    { key: ['built_in'], values: ['true'], operator: FilterOperator.NotEq },
    ...(ids ? [{ key: ['internal_id'], values: ids }] : []),
    ...(excludedIds && excludedIds.length > 0 ? [{ key: ['internal_id'], values: excludedIds, operator: FilterOperator.NotEq }] : []),
  ];
  return {
    orderBy: ThemeOrdering.Name,
    orderMode: OrderingMode.Asc,
    filters: { mode: FilterMode.And, filters, filterGroups: [] },
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

const brandingImporter: ConfigPresetImporter = {
  compute: async (context, user, item, plan, mode): Promise<ConfigPresetComputedItem> => {
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
    // Decided again by the theme module as it writes: a theme with this standard id created since compute is overwritten, never duplicated
    const result = await importTheme(context, user, item.configuration, { mode });
    if (result.status !== 'created' && result.status !== 'overwritten') {
      throw FunctionalError(result.reason ?? 'Theme cannot be imported');
    }
    return result.status === computed.status ? undefined : result.status;
  },
};

// Branding: the themes, paged and searched through the theme domain
export const brandingFamily: ConfigPresetFamilyDefinition = {
  importer: brandingImporter,
  // The themes that exist can be overwritten or copied
  importModes: [ConfigImportMode.Overwrite, ConfigImportMode.Copy],
  id: BRANDING_FAMILY_ID,
  label: 'Branding',
  description: 'Themes, colors, logos',
  group: platformSettingsGroup,
  directory: 'platform_settings/branding',
  listItems: async (context, user, args) => {
    const { first, after, search, ids, excludedIds } = args;
    // An empty list of ids is no theme: as a filter value it would match every theme
    if (ids?.length === 0) {
      return buildConfigPresetConnection(args, [], 0, false);
    }
    const [page, defaultTheme] = await Promise.all([
      findThemePaginated(context, user, { first, after, search, ...themesArgs(ids, excludedIds) }),
      getPlatformDefaultTheme(context, user),
    ]);
    const edges = page.edges.map(({ cursor, node }) => ({ cursor, node: toThemeItem(node, defaultTheme?.id) }));
    return buildConfigPresetConnection(args, edges, page.pageInfo.globalCount, page.pageInfo.hasNextPage);
  },
  resolveItems: async (context, user, ids, excludedIds) => {
    if (ids?.length === 0) {
      return [];
    }
    const [themes, defaultTheme] = await Promise.all([findAllThemes(context, user, themesArgs(ids, excludedIds)), getPlatformDefaultTheme(context, user)]);
    return themes.map((theme) => toThemeItem(theme, defaultTheme?.id));
  },
};
