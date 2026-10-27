import type { AuthContext, AuthUser } from '../../../types/user';
import { getPlatformConfigPresetConfiguration, getPlatformDefaultTheme } from '../../../domain/settings';
import { findById as findThemeById } from '../../theme/theme-domain';
import type { ConfigPresetFamilyDefinition, ConfigPresetItemDefinition } from '../configPreset-types';
import { type ConfigPresetComputedItem, type ConfigPresetImporter, configPresetPlanKey } from '../configPreset-import-types';
import { buildImportFields, importFailureReason, isNothingToImport } from '../configPreset-import-utils';
import { platformConfigurationSchema } from '../configPreset-import-schemas';
import { platformSettingsGroup, staticFamily } from './common-configPreset-registry';
import { BRANDING_FAMILY_ID } from './branding-configPreset-registry';

export const PLATFORM_FAMILY_ID = 'platform';
const PLATFORM_ITEM_ID = 'platform';
const PLATFORM_LABEL = 'Platform configuration';
const PLATFORM_IMPORT_KEYS = ['platform_title', 'platform_favicon'];
const PLATFORM_VALUE_KEYS = ['platform_title', 'platform_favicon', 'platform_language'];

// Title, favicon, language and the default theme reference. A custom default theme is a dependency;
// a built-in one exists on every platform, the reference names it anyway. The reference is built from the theme
// the dependency was computed with, so that both agree even if the default theme changes during the export.
const getPlatformItems = async (context: AuthContext, user: AuthUser): Promise<ConfigPresetItemDefinition[]> => {
  const defaultTheme = await getPlatformDefaultTheme(context, user);
  return [{
    id: PLATFORM_ITEM_ID,
    label: PLATFORM_LABEL,
    translatable: true,
    dependsOn: defaultTheme && !defaultTheme.built_in ? [{ type: BRANDING_FAMILY_ID, id: defaultTheme.id }] : [],
    exporter: (ctx, usr) => getPlatformConfigPresetConfiguration(ctx, usr, defaultTheme ?? null),
  }];
};

const platformImporter: ConfigPresetImporter = {
  compute: async (context, user, item, plan): Promise<ConfigPresetComputedItem> => {
    const base = { label: PLATFORM_LABEL, translatable: true, exists: true };
    const parsed = platformConfigurationSchema.safeParse(item.configuration);
    if (item.id !== PLATFORM_ITEM_ID) {
      return { ...base, status: 'failed', reason: 'Unexpected item id', fields: [] };
    }
    if (!parsed.success) {
      return { ...base, status: 'failed', reason: importFailureReason(parsed.error), fields: [] };
    }
    const configuration = parsed.data;
    const fields = buildImportFields(context, configuration, PLATFORM_IMPORT_KEYS, ['platform_favicon']);
    const defaultTheme = configuration.default_theme;
    if (isNothingToImport(configuration, PLATFORM_VALUE_KEYS) && !defaultTheme) {
      return { ...base, status: 'skipped', reason: 'Nothing to import', fields };
    }
    if (defaultTheme) {
      // Resolved by standard id on the platform, or among the themes this import creates
      const theme = await findThemeById(context, user, defaultTheme.standard_id);
      if (!theme && !plan.created.has(configPresetPlanKey(BRANDING_FAMILY_ID, defaultTheme.standard_id))) {
        return { ...base, status: 'failed', reason: `Default theme ${defaultTheme.name} could not be imported`, fields };
      }
    }
    return { ...base, status: 'overwritten', fields };
  },
};

export const platformFamily: ConfigPresetFamilyDefinition = {
  ...staticFamily({
    id: PLATFORM_FAMILY_ID,
    label: PLATFORM_LABEL,
    description: 'Title, favicon, default theme, language',
    group: platformSettingsGroup,
    directory: 'platform_settings',
  }, getPlatformItems),
  importer: platformImporter,
};
