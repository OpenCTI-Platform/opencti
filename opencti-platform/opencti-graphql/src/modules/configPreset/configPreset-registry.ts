import { PLATFORM_VERSION } from '../../config/conf';
import type { AuthContext, AuthUser } from '../../types/user';
import { getMessagesConfigPresetConfiguration, getPlatformConfigPresetConfiguration } from '../../domain/settings';
import { getPlatformHiddenEntityTypes } from '../entitySetting/entitySetting-domain';
import type { ConfigPresetFamilyDefinition, ConfigPresetItemDefinition, ConfigPresetItemFile } from './configPreset-types';

// Export groups of the spec table; a group is added with its first category
const platformSettingsGroup = { id: 'platformSettings', label: 'Platform settings' };
const dataModelGroup = { id: 'dataModel', label: 'Data model' };

// Theme and branding are not part of a configuration preset: they are left out of this category on purpose for now.
const platformItem: ConfigPresetItemDefinition = {
  id: 'platform',
  label: 'Platform configuration',
  translatable: true,
  exporter: (context) => getPlatformConfigPresetConfiguration(context),
};

const messagesItem: ConfigPresetItemDefinition = {
  id: 'messages',
  label: 'Messages',
  translatable: true,
  exporter: (context) => getMessagesConfigPresetConfiguration(context),
};

const hiddenEntityTypesItem: ConfigPresetItemDefinition = {
  id: 'hiddenEntityTypes',
  label: 'Hidden entity types',
  translatable: true,
  fileName: 'hidden_entity_types.json',
  exporter: async (context, user) => ({ hidden_entity_types: await getPlatformHiddenEntityTypes(context, user) }),
};

// Singleton categories: each one has one item with its own id
export const CONFIG_PRESET_FAMILIES: ConfigPresetFamilyDefinition[] = [
  {
    id: 'platform',
    label: 'Platform configuration',
    group: platformSettingsGroup,
    directory: 'platform_settings',
    listItems: async () => [platformItem],
  },
  {
    id: 'messages',
    label: 'Messages',
    group: platformSettingsGroup,
    directory: 'platform_settings',
    listItems: async () => [messagesItem],
  },
  {
    id: 'hiddenEntityTypes',
    label: 'Hidden entity types',
    group: dataModelGroup,
    directory: 'data_model',
    listItems: async () => [hiddenEntityTypesItem],
  },
];

export const configPresetItemFilePath = (family: ConfigPresetFamilyDefinition, item: ConfigPresetItemDefinition) => {
  return `${family.directory}/${item.fileName ?? `${item.id}.json`}`;
};

export const exportConfigPresetItem = async (
  context: AuthContext,
  user: AuthUser,
  family: ConfigPresetFamilyDefinition,
  item: ConfigPresetItemDefinition,
): Promise<ConfigPresetItemFile> => {
  return {
    openCTI_version: PLATFORM_VERSION,
    type: `${family.id}.${item.id}`,
    configuration: await item.exporter(context, user),
  };
};
