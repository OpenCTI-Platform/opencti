import type { AuthContext, AuthUser } from '../../../types/user';
import { getPlatformDefaultTheme } from '../../../domain/settings';
import { getPlatformConfigPresetConfiguration } from '../../settings/settings-export';
import { importPlatformConfiguration } from '../../settings/settings-import';
import type { ConfigPresetFamilyDefinition, ConfigPresetItemDefinition } from '../configPreset-types';
import { type ConfigPresetComputedItem, type ConfigPresetImporter, configPresetPlanKey } from '../import/configPreset-import-types';
import { buildImportFields } from '../import/configPreset-import-utils';
import { platformSettingsGroup, staticFamily, toAppliedStatus, toComputedItem } from './common-configPreset-registry';
import { BRANDING_FAMILY_ID } from './branding-configPreset-registry';

export const PLATFORM_FAMILY_ID = 'platform';
const PLATFORM_ITEM_ID = 'platform';
const PLATFORM_LABEL = 'Platform configuration';
const PLATFORM_IMPORT_KEYS = ['platform_title', 'platform_favicon'];

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
  compute: async (context, user, item, plan, mode): Promise<ConfigPresetComputedItem> => {
    const label = { label: PLATFORM_LABEL, translatable: true };
    if (item.id !== PLATFORM_ITEM_ID) {
      return { ...label, exists: true, conflict: false, status: 'failed', reason: 'Unexpected item id', fields: [] };
    }
    // A default theme this import creates is a theme the platform will have
    const isThemeCreated = (standardId: string) => plan.created.has(configPresetPlanKey(BRANDING_FAMILY_ID, standardId));
    const result = await importPlatformConfiguration(context, user, item.configuration, { mode, dryRun: true, isThemeCreated });
    return toComputedItem(label, result, result.configuration ? buildImportFields(result.configuration, PLATFORM_IMPORT_KEYS) : []);
  },
  apply: async (context, user, item, computed, mode) => {
    return toAppliedStatus(await importPlatformConfiguration(context, user, item.configuration, { mode }), computed);
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
