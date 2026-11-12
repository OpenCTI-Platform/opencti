import type { AuthContext, AuthUser } from '../../../types/user';
import { ConfigImportMode, type ConfigImportStatus } from '../../configImport/configImport-types';
import type { ConfigPresetConfiguration } from '../configPreset-types';

// Reasons of a refusal, read by the front in extensions.data.reason (the message is only for display)
export const CONFIG_PRESET_REASON_FILE_MISSING = 'file_missing';
export const CONFIG_PRESET_REASON_BUNDLE_REFUSED = 'bundle_refused';

// Why an item of a family that requires the Enterprise Edition is skipped on a platform without it: shown to the user as is (the front translates it)
export const CONFIG_PRESET_REASON_ENTERPRISE_EDITION_REQUIRED = 'Requires Enterprise Edition';

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
  // The attachment of the item in the zip (the values of an exclusion list): absent when the item has none, or when the zip lacks it
  attachment?: ConfigPresetBundleAttachment;
}

export interface ConfigPresetBundleAttachment {
  // Path in the zip
  path: string;
  // Reads the attachment when it is needed, never while the bundle is read. The limit is enforced on the bytes really read:
  // null when the attachment is bigger, nothing is kept of it.
  read: (limit: number) => Promise<Buffer | null>;
}

// What an importer decides for an item, without writing anything
export interface ConfigPresetComputedItem {
  status: ConfigImportStatus;
  reason?: string;
  // Why, for the UI to tell apart without reading the reason: the code of the module that decided it
  code?: string;
  label: string;
  // True when the label is a static string the UI translates
  translatable: boolean;
  // Whether the item already exists on the platform
  exists: boolean;
  // Whether the item conflicts with one of the platform (it exists, or another one has its name): the user chooses what to do with it
  conflict: boolean;
  // The values the preview shows of the item, when it shows some
  fields?: ConfigPresetImportField[];
  // A setting that is on or off: whether the bundle turns it on, shown under its label; null when the bundle does not set it
  isEnabled?: boolean | null;
}

// What the import would create, shared by the items of one import: `<type>/<bundle id>`
export interface ConfigPresetImportPlan {
  created: Set<string>;
  // The theme names the earlier items of a dry run would take, which writes nothing: an import reads the platform before each item
  themeNames?: Set<string>;
  // The names that the themes the earlier items of a dry run would rename no longer hold
  releasedThemeNames?: Set<string>;
  // The names (normalized) of the exclusion lists the earlier items of an import hold, dry run or not
  exclusionListNames?: Set<string>;
  // The standard ids of the roles the earlier items of a dry run would create
  roleIds?: Set<string>;
  // The standard ids of the groups the earlier items of a dry run would create
  groupIds?: Set<string>;
  // Whether the roles the earlier items of a dry run would create or overwrite give sensitive rights, by the standard id they are written under
  roleSensitiveRights?: Map<string, boolean>;
  // The markings the earlier items of a dry run would create or whose order they would change, as they will be once written, by standard id
  plannedMarkings?: Map<string, { definition_type: string; definition: string; x_opencti_order: number }>;
  // `<type>/<bundle id>` -> the standard id the item is written under (its copy when imported as COPY), null when the copy is not written.
  // The items that depend on it use it, so that they get the item of the bundle and never the local one with its bundle id
  targets?: Map<string, string | null>;
}

export const configPresetPlanKey = (type: string, id: string) => `${type}/${id}`;

export const recordConfigPresetTarget = (plan: ConfigPresetImportPlan, type: string, id: string, target: string | null) => {
  plan.targets?.set(configPresetPlanKey(type, id), target);
};

// The bundle ids of the items of one family the import creates
export const configPresetCreated = (plan: ConfigPresetImportPlan, type: string) => {
  const prefix = configPresetPlanKey(type, '');
  return new Set([...plan.created].filter((key) => key.startsWith(prefix)).map((key) => key.slice(prefix.length)));
};

// The targets of the items of one family, by bundle id
export const configPresetTargets = (plan: ConfigPresetImportPlan, type: string) => {
  const prefix = configPresetPlanKey(type, '');
  return new Map([...(plan.targets ?? [])].filter(([key]) => key.startsWith(prefix)).map(([key, target]) => [key.slice(prefix.length), target]));
};

export interface ConfigPresetImporter {
  // Reads only: finds the existing item, validates, decides the result and records in the plan what it would create
  compute: (context: AuthContext, user: AuthUser, item: ConfigPresetBundleItem, plan: ConfigPresetImportPlan, mode: ConfigImportMode) => Promise<ConfigPresetComputedItem>;
  // Writes the item, with one domain call when it can: an importer that needs several (the hidden entity types hide, then show) can leave
  // its item half written, and the error then makes it failed.
  // Returns the status when it differs from the computed one (a theme created by another import since compute is overwritten).
  // The plan is the one compute recorded this item and the earlier ones in (the role a group gets)
  apply: (
    context: AuthContext,
    user: AuthUser,
    item: ConfigPresetBundleItem,
    computed: ConfigPresetComputedItem,
    mode: ConfigImportMode,
    plan: ConfigPresetImportPlan,
  ) => Promise<ConfigImportStatus | void>;
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
