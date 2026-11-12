import type { ConfigImportMode } from '../../configImportMode';

interface PartialImportItem {
  key: string;
  conflict: boolean;
}

// Every item of the bundle is selected at first: the user picks the ones to leave out
export const partialImportSelectedKeys = (items: ReadonlyArray<{ key: string }>): ReadonlySet<string> => new Set(items.map(({ key }) => key));

export const toggleSelectedKey = (selected: ReadonlySet<string>, key: string): ReadonlySet<string> => {
  const next = new Set(selected);
  if (next.has(key)) {
    next.delete(key);
  } else {
    next.add(key);
  }
  return next;
};

// The mode of each selected item in conflict, the default one when the user chose none: always sent, so the import does what the
// dialog showed whatever the default of the backend. An item without conflict needs none.
export const partialImportItemModes = (
  items: ReadonlyArray<PartialImportItem>,
  modes: Readonly<Record<string, ConfigImportMode>>,
  defaultMode: ConfigImportMode,
): { key: string; mode: ConfigImportMode }[] => {
  return items.filter(({ conflict }) => conflict).map(({ key }) => ({ key, mode: modes[key] ?? defaultMode }));
};

// The selected items in conflict: the ones a mode is chosen for. The choice for all of them is offered from two, as in the wizard:
// with one, its own choice is enough
export const partialImportConflictKeys = (items: ReadonlyArray<PartialImportItem>, selected: ReadonlySet<string>): string[] => {
  return items.filter(({ key, conflict }) => conflict && selected.has(key)).map(({ key }) => key);
};

// The mode the items share, null when they differ: the choice for all of them then shows Mixed
export const sharedPartialImportMode = (
  modes: Readonly<Record<string, ConfigImportMode>>,
  keys: ReadonlyArray<string>,
  defaultMode: ConfigImportMode,
): ConfigImportMode | null => {
  const shared = new Set(keys.map((key) => modes[key] ?? defaultMode));
  return shared.size === 1 ? [...shared][0] : null;
};

// The same mode for all the given items
export const withPartialImportModeForItems = (
  modes: Readonly<Record<string, ConfigImportMode>>,
  keys: ReadonlyArray<string>,
  mode: ConfigImportMode,
): Record<string, ConfigImportMode> => {
  return { ...modes, ...Object.fromEntries(keys.map((key) => [key, mode])) };
};
