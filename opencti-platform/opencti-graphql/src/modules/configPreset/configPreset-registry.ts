import { PLATFORM_VERSION } from '../../config/conf';
import type { AuthContext, AuthUser } from '../../types/user';
import type { ConfigPresetFamilyDefinition, ConfigPresetItemDefinition, ConfigPresetItemFile } from './configPreset-types';
import { platformFamily } from './registry/platform-configPreset-registry';
import { brandingFamily } from './registry/branding-configPreset-registry';
import { messagesFamily } from './registry/messages-configPreset-registry';
import { hiddenEntityTypesFamily } from './registry/hiddenEntityTypes-configPreset-registry';

export { BRANDING_FAMILY_ID } from './registry/branding-configPreset-registry';

// In registry order, the categories of the spec table: Platform settings (platform, branding, messages), then Data model.
// Each family is defined in its own file under registry/.
export const CONFIG_PRESET_FAMILIES: ConfigPresetFamilyDefinition[] = [
  platformFamily,
  brandingFamily,
  messagesFamily,
  hiddenEntityTypesFamily,
];

export const configPresetItemFilePath = (family: ConfigPresetFamilyDefinition, item: ConfigPresetItemDefinition) => {
  return `${family.directory}/${item.fileName ?? `${item.id}.json`}`;
};

export const configPresetItemBundleId = (item: ConfigPresetItemDefinition) => item.bundleId ?? item.id;

// Whether an item of a bundle needs the Enterprise Edition: the flag of the item, else the one of its family, else false.
// familyId is the bare family id (the type of an item file is `<group>.<family>`).
export const configPresetRequiresEnterpriseEdition = (familyId: string, bundleId: string): boolean => {
  const family = CONFIG_PRESET_FAMILIES.find(({ id }) => id === familyId);
  const item = family?.staticItems?.find((candidate) => configPresetItemBundleId(candidate) === bundleId);
  return item?.requiresEnterpriseEdition ?? family?.requiresEnterpriseEdition ?? false;
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
    // The bundle id, never an internal id: the static item id, or the standard id of an entity
    id: configPresetItemBundleId(item),
    configuration: await item.exporter(context, user),
  };
};
