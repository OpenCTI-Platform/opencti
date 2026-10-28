// What an import does with the items of a type that already exist: patches them, or adds them under a free name.
// The values of the ConfigImportMode enum of the schema that a type offers (ADD is for the import of a single item)
export type ConfigImportMode = 'OVERWRITE' | 'COPY';

// By type key; a type that overwrites has no entry, that is what the backend does when there is no mode
export type ConfigImportModes = Record<string, ConfigImportMode>;

export const DEFAULT_CONFIG_IMPORT_MODE: ConfigImportMode = 'OVERWRITE';

export const CONFIG_IMPORT_MODE_LABELS: Record<ConfigImportMode, string> = {
  OVERWRITE: 'Overwrite',
  COPY: 'Add as a copy',
};

export const isConfigImportMode = (mode: string): mode is ConfigImportMode => mode in CONFIG_IMPORT_MODE_LABELS;

// The mode of a type, without the default one
export const withConfigImportMode = (modes: ConfigImportModes, typeKey: string, mode: ConfigImportMode): ConfigImportModes => {
  const { [typeKey]: _previous, ...others } = modes;
  return mode === DEFAULT_CONFIG_IMPORT_MODE ? others : { ...others, [typeKey]: mode };
};
