import type { AuthContext, AuthUser } from '../../types/user';
import type { ConfigPresetConfiguration } from './configPreset-types';

// Reasons of a refusal, read by the front in extensions.data.reason (the message is only for display)
export const CONFIG_PRESET_REASON_FILE_MISSING = 'file_missing';
export const CONFIG_PRESET_REASON_BUNDLE_REFUSED = 'bundle_refused';

export type ConfigPresetImportStatus = 'created' | 'overwritten' | 'skipped' | 'failed';

// A value the import would write; null means untouched. external_host: a URL whose host is not the platform's.
export interface ConfigPresetImportField {
  key: string;
  value: string | null;
  external_host: boolean;
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
  status: ConfigPresetImportStatus;
  reason?: string;
  label: string;
  // True when the label is a static string the UI translates
  translatable: boolean;
  // Whether the item already exists on the platform
  exists: boolean;
  fields: ConfigPresetImportField[];
}

// What the import would create, shared by the items of one import: `<type>/<bundle id>`
export interface ConfigPresetImportPlan {
  created: Set<string>;
}

export const configPresetPlanKey = (type: string, id: string) => `${type}/${id}`;

export interface ConfigPresetImporter {
  // Reads only: finds the existing item, validates, decides the result and records in the plan what it would create
  compute: (context: AuthContext, user: AuthUser, item: ConfigPresetBundleItem, plan: ConfigPresetImportPlan) => Promise<ConfigPresetComputedItem>;
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
