import { PLATFORM_VERSION } from '../../config/conf';
import type { AuthContext, AuthUser } from '../../types/user';
import type { ConfigPresetFamilyDefinition, ConfigPresetItemDefinition, ConfigPresetItemFile } from './configPreset-types';
import { platformFamily } from './registry/platform-configPreset-registry';
import { brandingFamily } from './registry/branding-configPreset-registry';
import { messagesFamily } from './registry/messages-configPreset-registry';
import { hiddenEntityTypesFamily } from './registry/hiddenEntityTypes-configPreset-registry';
import { rolesFamily } from './registry/roles-configPreset-registry';
import { groupsFamily } from './registry/groups-configPreset-registry';

export { BRANDING_FAMILY_ID } from './registry/branding-configPreset-registry';

// In registry order, the categories of the spec table: Platform settings (platform, branding, messages), then Data model, then Security & Access.
// Each family is defined in its own file under registry/.
export const CONFIG_PRESET_FAMILIES: ConfigPresetFamilyDefinition[] = [
  platformFamily,
  brandingFamily,
  messagesFamily,
  hiddenEntityTypesFamily,
  rolesFamily,
  groupsFamily,
];

// How the result of an item is shown next to its family: the name of its type, its place in the registry and its group.
// A type the registry does not know (a bundle of a newer platform) is its own group.
export const getConfigPresetFamilyDisplay = (type: string) => {
  const index = CONFIG_PRESET_FAMILIES.findIndex(({ id }) => id === type);
  const family = CONFIG_PRESET_FAMILIES[index];
  return {
    type_label: family?.label ?? type,
    type_index: Math.max(index, 0),
    group: family ? { key: family.group.id, label: family.group.label } : { key: type, label: type },
  };
};

export const configPresetItemFilePath = (family: ConfigPresetFamilyDefinition, item: ConfigPresetItemDefinition) => {
  return `${family.directory}/${item.fileName ?? `${item.id}.json`}`;
};

// The type written in the item files and in dependencies.json: `<group id>.<category id>`
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
    // The id of the item: the static id, or the standard id of an entity, never an internal id
    id: item.id,
    configuration: await item.exporter(context, user),
  };
};
