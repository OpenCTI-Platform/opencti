import { PLATFORM_VERSION } from '../../config/conf';
import type { AuthContext, AuthUser } from '../../types/user';
import type { ConfigPresetFamilyDefinition, ConfigPresetItemDefinition, ConfigPresetItemFile, ConfigPresetItemFileDefinition } from './configPreset-types';
import { platformFamily } from './registry/platform-configPreset-registry';
import { brandingFamily } from './registry/branding-configPreset-registry';
import { messagesFamily } from './registry/messages-configPreset-registry';
import { hiddenEntityTypesFamily } from './registry/hiddenEntityTypes-configPreset-registry';
import { whitemarkFamily } from './registry/whitemark-configPreset-registry';
import { labelsFamily } from './registry/labels-configPreset-registry';
import { isEnterpriseEditionUpToDate } from '../../enterprise-edition/ee';
import { killChainPhasesFamily } from './registry/killChainPhases-configPreset-registry';
import { vocabulariesFamily } from './registry/vocabularies-configPreset-registry';
import { statusTemplatesFamily } from './registry/statusTemplates-configPreset-registry';
import { caseTemplatesFamily } from './registry/caseTemplates-configPreset-registry';
import { exclusionListsFamily } from './registry/exclusionLists-configPreset-registry';

export { BRANDING_FAMILY_ID } from './registry/branding-configPreset-registry';

// In registry order, the categories of the spec table: Platform settings (platform, branding, messages, whitemark), Data model, then Taxonomy, then Customization.
// Each family is defined in its own file under registry/.
export const CONFIG_PRESET_FAMILIES: ConfigPresetFamilyDefinition[] = [
  platformFamily,
  brandingFamily,
  messagesFamily,
  whitemarkFamily,
  hiddenEntityTypesFamily,
  labelsFamily,
  killChainPhasesFamily,
  vocabulariesFamily,
  statusTemplatesFamily,
  caseTemplatesFamily,
  exclusionListsFamily,
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

// A family that requires the Enterprise Edition is only available on a platform that has it: the single place that knows
// the rule, for the export and the import of any family that sets requiresEnterpriseEdition.
// The license is read from the database: the screens ask right after a license was activated, which the settings cache may not know yet.
export const isConfigPresetFamilyAvailable = async (context: AuthContext, family: ConfigPresetFamilyDefinition) => {
  return !family.requiresEnterpriseEdition || isEnterpriseEditionUpToDate(context);
};

export const configPresetItemFilePath = (family: ConfigPresetFamilyDefinition, item: ConfigPresetItemDefinition) => {
  return `${family.directory}/${item.fileName ?? `${item.id}.json`}`;
};

// The path from the zip root of the file an item carries, next to its JSON
export const configPresetItemAttachedFilePath = (family: ConfigPresetFamilyDefinition, file: ConfigPresetItemFileDefinition) => {
  return `${family.directory}/${file.name}`;
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
    ...(item.file ? { file: configPresetItemAttachedFilePath(family, item.file) } : {}),
  };
};
