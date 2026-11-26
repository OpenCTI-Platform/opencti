import semver from 'semver';
import { PLATFORM_VERSION } from '../../../config/conf';
import type { ConfigPresetFamilyDefinition } from '../configPreset-types';
import type { ConfigPresetBundleItem, ConfigPresetComputedItem } from './configPreset-import-types';
import { CONFIG_PRESET_CODE_INCOMPATIBLE_VERSION } from './configPreset-import-types';

// The first release that exports a configuration bundle
export const CONFIG_PRESET_MINIMAL_COMPATIBLE_VERSION = '7.261021.0';

// Why the platform cannot import an item, from the version it was exported with; null when it can
export const getConfigPresetItemIncompatibility = (family: ConfigPresetFamilyDefinition, version: string | undefined): string | null => {
  if (version === undefined) {
    return null;
  }
  const itemVersion = semver.coerce(version);
  if (!itemVersion) {
    return `Unreadable version: ${version}`;
  }
  if (semver.gt(itemVersion, semver.coerce(PLATFORM_VERSION)!)) {
    return `Exported from a more recent platform: ${version}`;
  }
  const minimalVersion = family.minimalCompatibleVersion ?? CONFIG_PRESET_MINIMAL_COMPATIBLE_VERSION;
  if (semver.lt(itemVersion, minimalVersion)) {
    return `Exported from a version that is no longer supported: ${version} (minimum ${minimalVersion})`;
  }
  return null;
};

const incompatibleItemLabel = (family: ConfigPresetFamilyDefinition, item: ConfigPresetBundleItem) => {
  if (item.id === family.id) {
    return { label: family.label, translatable: true };
  }
  const { name } = item.configuration;
  return { label: typeof name === 'string' && name.trim() ? name : item.id, translatable: false };
};

export const computeIncompatibleConfigPresetItem = (family: ConfigPresetFamilyDefinition, item: ConfigPresetBundleItem): ConfigPresetComputedItem | null => {
  const reason = getConfigPresetItemIncompatibility(family, item.openCTI_version);
  if (!reason) {
    return null;
  }
  return { ...incompatibleItemLabel(family, item), exists: false, conflict: false, status: 'skipped', reason, code: CONFIG_PRESET_CODE_INCOMPATIBLE_VERSION };
};
