import type { AuthContext, AuthUser } from '../../../types/user';
import { ConfigImportMode, type ConfigImportStatus } from '../../configImport/configImport-types';
import type { ConfigPresetConfiguration } from '../configPreset-types';

// Reasons of a refusal, read by the front in extensions.data.reason (the message is only for display)
export const CONFIG_PRESET_REASON_FILE_MISSING = 'file_missing';
export const CONFIG_PRESET_REASON_BUNDLE_REFUSED = 'bundle_refused';

// What an import does with the items of a family that already exist, chosen by family: a family without a choice overwrites
export const CONFIG_PRESET_DEFAULT_IMPORT_MODE = ConfigImportMode.Overwrite;

// A value the import would write; null means untouched
export interface ConfigPresetImportField {
  key: string;
  value: string | null;
}

// An item of the bundle, found by its type (the bare family id) and its bundle id
export interface ConfigPresetBundleItem {
  // Bare family id, not `<group>.<family>`
  type: string;
  // Bundle id
  id: string;
  // Path in the zip
  path: string;
  configuration: ConfigPresetConfiguration;
}

// What an importer decides for an item, without writing anything
export interface ConfigPresetComputedItem {
  status: ConfigImportStatus;
  reason?: string;
  label: string;
  // True when the label is a static string the UI translates
  translatable: boolean;
  // Whether the item already exists on the platform
  exists: boolean;
  // Whether the item conflicts with one of the platform (it exists, or another one has its name): the user chooses what to do with it
  conflict: boolean;
  fields: ConfigPresetImportField[];
}

// What the import would create, shared by the items of one import: `<type>/<bundle id>`
export interface ConfigPresetImportPlan {
  created: Set<string>;
}

export const configPresetPlanKey = (type: string, id: string) => `${type}/${id}`;

export interface ConfigPresetImporter {
  // Reads only: finds the existing item, validates, decides the result and records in the plan what it would create
  compute: (context: AuthContext, user: AuthUser, item: ConfigPresetBundleItem, plan: ConfigPresetImportPlan, mode: ConfigImportMode) => Promise<ConfigPresetComputedItem>;
  // Writes the item with one domain call, so that a failure never leaves it half written; an error makes the item failed.
  // Returns the status when it differs from the computed one (a theme created by another import since compute is overwritten).
  apply: (context: AuthContext, user: AuthUser, item: ConfigPresetBundleItem, computed: ConfigPresetComputedItem, mode: ConfigImportMode) => Promise<ConfigImportStatus | void>;
}

// Content of metadata.json
export interface ConfigPresetBundleMetadata {
  openCTI_version: string;
  generated_at: string;
  bundle_name: string | null;
}

export interface ConfigPresetBundle {
  metadata: ConfigPresetBundleMetadata;
  items: ConfigPresetBundleItem[];
  // `<group>.<family>` -> bundle id -> bundle id of a dependency -> its path in the zip
  dependencies: Record<string, Record<string, Record<string, string>>>;
  // Entries of the zip that are not an importable item
  ignored: string[];
}
