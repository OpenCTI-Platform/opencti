import type { AuthContext, AuthUser } from '../../../types/user';
import { getPlatformConfigPresetConfiguration, getPlatformDefaultTheme } from '../../../domain/settings';
import type { ConfigPresetFamilyDefinition, ConfigPresetItemDefinition } from '../configPreset-types';
import { platformSettingsGroup, staticFamily } from './common-configPreset-registry';
import { BRANDING_FAMILY_ID } from './branding-configPreset-registry';

// Title, favicon, language and the default theme reference. A custom default theme is a dependency;
// a built-in one exists on every platform, the reference names it anyway.
const getPlatformItems = async (context: AuthContext, user: AuthUser): Promise<ConfigPresetItemDefinition[]> => {
  const defaultTheme = await getPlatformDefaultTheme(context, user);
  return [{
    id: 'platform',
    label: 'Platform configuration',
    translatable: true,
    dependsOn: defaultTheme && !defaultTheme.built_in ? [{ type: BRANDING_FAMILY_ID, id: defaultTheme.id }] : [],
    exporter: (ctx, usr) => getPlatformConfigPresetConfiguration(ctx, usr),
  }];
};

export const platformFamily: ConfigPresetFamilyDefinition = staticFamily({
  id: 'platform',
  label: 'Platform configuration',
  description: 'Title, favicon, default theme, language',
  group: platformSettingsGroup,
  directory: 'platform_settings',
}, getPlatformItems);
