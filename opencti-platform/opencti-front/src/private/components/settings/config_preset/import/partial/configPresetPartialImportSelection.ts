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
