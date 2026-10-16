import { PLATFORM_VERSION } from '../../config/conf';
import type { AuthContext, AuthUser } from '../../types/user';
import type { ConfigPresetFamilyDefinition, ConfigPresetItemDefinition, ConfigPresetItemFile } from './configPreset-types';
import { platformFamily } from './registry/platform-configPreset-registry';
import { messagesFamily } from './registry/messages-configPreset-registry';
import { hiddenEntityTypesFamily } from './registry/hiddenEntityTypes-configPreset-registry';

// Singleton categories: each one has one item with its own id. Each family is defined in its own file under registry/.
export const CONFIG_PRESET_FAMILIES: ConfigPresetFamilyDefinition[] = [
  platformFamily,
  messagesFamily,
  hiddenEntityTypesFamily,
];

export const configPresetItemFilePath = (family: ConfigPresetFamilyDefinition, item: ConfigPresetItemDefinition) => {
  return `${family.directory}/${item.fileName ?? `${item.id}.json`}`;
};

// The type written in the item files: `<group id>.<category id>`
export const configPresetFamilyType = (family: ConfigPresetFamilyDefinition) => `${family.group.id}.${family.id}`;

export const exportConfigPresetItem = async (
  context: AuthContext,
  user: AuthUser,
  family: ConfigPresetFamilyDefinition,
  item: ConfigPresetItemDefinition,
): Promise<ConfigPresetItemFile> => {
  return {
    openCTI_version: PLATFORM_VERSION,
    type: configPresetFamilyType(family),
    id: item.id,
    configuration: await item.exporter(context, user),
  };
};
