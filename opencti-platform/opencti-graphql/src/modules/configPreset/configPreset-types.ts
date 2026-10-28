import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicConnection } from '../../types/store';
import type { ConfigPresetImporter } from './import/configPreset-import-types';
import type { ConfigImportMode } from '../configImport/configImport-types';

export type ConfigPresetConfiguration = Record<string, unknown>;

// Content of the JSON file written for one item
export interface ConfigPresetItemFile {
  openCTI_version: string;
  // `<group id>.<category id>`
  type: string;
  // Bundle id of the item
  id: string;
  configuration: ConfigPresetConfiguration;
}

// An item of a type, by API ids
export interface ConfigPresetItemReference {
  type: string;
  id: string;
}

export interface ConfigPresetItemDefinition {
  // API id: the category id for a singleton, the internal id for an entity
  id: string;
  // Id in the bundle, the same on every platform: the standard id for an entity, the API id when absent
  bundleId?: string;
  label: string;
  // True when the label is a static string the UI translates; false when it is user data (an entity name)
  translatable: boolean;
  // File name of the item in the family folder, `${id}.json` when absent
  fileName?: string;
  // The platform default (the default theme)
  isDefault?: boolean;
  // Items exported with this one, whatever the selection
  dependsOn?: ConfigPresetItemReference[];
  // Returns the allowlisted configuration of the item, never secrets
  exporter: (context: AuthContext, user: AuthUser) => Promise<ConfigPresetConfiguration>;
}

export interface ConfigPresetListItemsArgs {
  first?: number | null;
  after?: string | null;
  search?: string | null;
  // Only these items
  ids?: string[] | null;
  // Every item but these
  excludedIds?: string[] | null;
}

// An export group of the spec table (Platform settings, Data model...): it groups categories in the export dialog
interface ConfigPresetGroupDefinition {
  id: string;
  label: string;
}

// A family is a category of the spec table (Platform, Messages, Hidden entity types...), in one export group.
// A category whose only item has the id of the category is a singleton: the dialog shows it as one checkbox.
// The items of an entity category are entities, whose ids are never a category id.
export interface ConfigPresetFamilyDefinition {
  id: string;
  label: string;
  // What the category holds, a static string the UI translates
  description: string;
  group: ConfigPresetGroupDefinition;
  // Folder of the family in the exported bundle: the group folder for a singleton category
  // (platform_settings, data_model), `<group folder>/<category folder>` for an entity category
  directory: string;
  // A page of the exportable items, in a stable order; an entity family delegates to the listing of its domain
  listItems: (context: AuthContext, user: AuthUser, args: ConfigPresetListItemsArgs) => Promise<BasicConnection<ConfigPresetItemDefinition>>;
  // Every exportable item (ids null) or only the given ones, without the excluded ones: what the export writes
  resolveItems: (context: AuthContext, user: AuthUser, ids: string[] | null, excludedIds: string[]) => Promise<ConfigPresetItemDefinition[]>;
  // How the items of this family are imported; a family without importer is reported as not importable
  importer?: ConfigPresetImporter;
  // What an import can do with the items that already exist: OVERWRITE when absent. The dialog offers a choice from two modes.
  importModes?: ConfigImportMode[];
}
