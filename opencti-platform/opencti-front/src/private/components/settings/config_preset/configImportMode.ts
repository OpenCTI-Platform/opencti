// What an import does with an item that already exists: patches it, or adds it under a free name.
// The values of the ConfigImportMode enum of the schema that a type offers (ADD is for the import of a single item)
export type ConfigImportMode = 'OVERWRITE' | 'COPY';

// By item, `<type key>/<item key>`; an item that overwrites has no entry, that is what the backend does when there is no mode
export type ConfigImportModes = Record<string, ConfigImportMode>;

export const DEFAULT_CONFIG_IMPORT_MODE: ConfigImportMode = 'OVERWRITE';

export const CONFIG_IMPORT_MODE_LABELS: Record<ConfigImportMode, string> = {
  OVERWRITE: 'Overwrite',
  COPY: 'Add as a copy',
};

export const isConfigImportMode = (mode: string): mode is ConfigImportMode => mode in CONFIG_IMPORT_MODE_LABELS;

export const configImportModeKey = (typeKey: string, itemKey: string) => `${typeKey}/${itemKey}`;

// The mode of an item, without the default one
export const withConfigImportMode = (modes: ConfigImportModes, typeKey: string, itemKey: string, mode: ConfigImportMode): ConfigImportModes => {
  const { [configImportModeKey(typeKey, itemKey)]: _previous, ...others } = modes;
  return mode === DEFAULT_CONFIG_IMPORT_MODE ? others : { ...others, [configImportModeKey(typeKey, itemKey)]: mode };
};

// The modes of the items of a type, as the mutation takes them
export const toItemModes = (modes: ConfigImportModes, typeKey: string): { key: string; mode: ConfigImportMode }[] => {
  const prefix = configImportModeKey(typeKey, '');
  return Object.entries(modes).filter(([key]) => key.startsWith(prefix)).map(([key, mode]) => ({ key: key.slice(prefix.length), mode }));
};

// The mode of several items at once, the ones of a type that conflict
export const withConfigImportModeForItems = (modes: ConfigImportModes, typeKey: string, itemKeys: ReadonlyArray<string>, mode: ConfigImportMode): ConfigImportModes => {
  return itemKeys.reduce((current, itemKey) => withConfigImportMode(current, typeKey, itemKey, mode), modes);
};

// The mode the items share, null when they differ
export const sharedConfigImportMode = (modes: ConfigImportModes, typeKey: string, itemKeys: ReadonlyArray<string>): ConfigImportMode | null => {
  const shared = new Set(itemKeys.map((itemKey) => modes[configImportModeKey(typeKey, itemKey)] ?? DEFAULT_CONFIG_IMPORT_MODE));
  return shared.size === 1 ? [...shared][0] : null;
};
