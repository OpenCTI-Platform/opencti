import { getPlatformConfigPresetConfiguration } from '../../../domain/settings';
import type { ConfigPresetFamilyDefinition, ConfigPresetItemDefinition } from '../configPreset-types';
import { platformSettingsGroup, staticFamily } from './common-configPreset-registry';

// Theme and branding are not part of a configuration preset: they are left out of this category on purpose for now.
const platformItem: ConfigPresetItemDefinition = {
  id: 'platform',
  label: 'Platform configuration',
  translatable: true,
  exporter: (context) => getPlatformConfigPresetConfiguration(context),
};

export const platformFamily: ConfigPresetFamilyDefinition = staticFamily({
  id: 'platform',
  label: 'Platform configuration',
  description: 'Title, favicon, language',
  group: platformSettingsGroup,
  directory: 'platform_settings',
}, async () => [platformItem]);
