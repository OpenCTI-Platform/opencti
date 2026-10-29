import { type ConfigImportMode, toItemModes } from './configImportMode';

// Selection of one type: every item but the item keys in ids ('all'), or only those ('some'; none when ids is empty)
export interface ConfigPresetTypeSelection {
  readonly mode: 'all' | 'some';
  readonly ids: readonly string[];
}

// By exportable type key
export type ConfigPresetSelection = Record<string, ConfigPresetTypeSelection>;
// Item keys exported because a selected item depends on them, by type key
export type ConfigPresetForcedItems = Record<string, readonly string[]>;
export type ConfigPresetItemsFilter = 'all' | 'selected' | 'excluded';

interface ExportableItem {
  readonly key: string;
  readonly dependsOn: ReadonlyArray<{ readonly type: string; readonly key: string }>;
}

interface CountedType {
  readonly key: string;
  readonly itemsPageInfo: { readonly globalCount: number };
}

interface ExportableType extends CountedType {
  // The first page of items
  readonly items: ReadonlyArray<ExportableItem>;
}

interface ConfigPresetSelectionInput {
  type: string;
  items: string[] | null;
  excluded_items?: string[];
  // Import only: the items that are not imported with the default mode
  item_modes?: { key: string; mode: ConfigImportMode }[];
}

const ALL: ConfigPresetTypeSelection = { mode: 'all', ids: [] };
const NONE: ConfigPresetTypeSelection = { mode: 'some', ids: [] };

const typeSelection = (selection: ConfigPresetSelection, typeKey: string) => selection[typeKey] ?? NONE;

// The export groups of the exportable types, in their order, each with its types
export const groupConfigPresetTypes = <T extends { readonly group: { readonly key: string; readonly label: string } }>(types: ReadonlyArray<T>) => {
  const groups: { key: string; label: string; types: T[] }[] = [];
  types.forEach((type) => {
    const group = groups.find(({ key }) => key === type.group.key);
    if (group) {
      group.types.push(type);
    } else {
      groups.push({ key: type.group.key, label: type.group.label, types: [type] });
    }
  });
  return groups;
};

// A singleton type has one item with the key of the type: it is shown as a single checkbox
export const isSingletonConfigPresetType = (type: { readonly key: string; readonly items: ReadonlyArray<{ readonly key: string }> }): boolean => {
  return type.items.length === 1 && type.items[0].key === type.key;
};

export const selectAllConfigPresetItems = (types: ReadonlyArray<{ readonly key: string }>): ConfigPresetSelection => {
  return Object.fromEntries(types.map((type) => [type.key, ALL]));
};

export const isConfigPresetItemSelected = (selection: ConfigPresetSelection, typeKey: string, itemKey: string): boolean => {
  const { mode, ids } = typeSelection(selection, typeKey);
  return mode === 'all' ? !ids.includes(itemKey) : ids.includes(itemKey);
};

// One level: the dependencies of the selected items the dialog has loaded (the first page of each type)
// TODO an entity type with dependencies beyond its first page, or chained ones, would show fewer forced items here
// than the export contains (the closure of the back end stays correct): load dependsOn in the sub-view and follow the chain
export const getConfigPresetForcedItems = (types: ReadonlyArray<ExportableType>, selection: ConfigPresetSelection): ConfigPresetForcedItems => {
  const forced: Record<string, string[]> = {};
  types.forEach((type) => type.items
    .filter((item) => isConfigPresetItemSelected(selection, type.key, item.key))
    .forEach((item) => item.dependsOn.forEach((dependency) => {
      forced[dependency.type] = [...(forced[dependency.type] ?? []), dependency.key];
    })));
  return forced;
};

export const countConfigPresetItems = (types: ReadonlyArray<CountedType>): number => {
  return types.reduce((count, type) => count + type.itemsPageInfo.globalCount, 0);
};

// A forced item counts as checked: it is exported whatever the selection
export const countConfigPresetCheckedItems = (types: ReadonlyArray<CountedType>, selection: ConfigPresetSelection, forced: ConfigPresetForcedItems): number => {
  return types.reduce((count, type) => {
    const { mode, ids } = typeSelection(selection, type.key);
    const forcedIds = forced[type.key] ?? [];
    if (mode === 'all') {
      return count + type.itemsPageInfo.globalCount - ids.filter((id) => !forcedIds.includes(id)).length;
    }
    return count + new Set([...ids, ...forcedIds]).size;
  }, 0);
};

// State of the checkbox of a type or a group: checked when all its items are, indeterminate when only some are
export const getConfigPresetCheckboxState = (
  types: ReadonlyArray<CountedType>,
  selection: ConfigPresetSelection,
  forced: ConfigPresetForcedItems,
): boolean | 'indeterminate' => {
  const checkedCount = countConfigPresetCheckedItems(types, selection, forced);
  if (checkedCount === 0) {
    return false;
  }
  return checkedCount === countConfigPresetItems(types) ? true : 'indeterminate';
};

// Every item or none, without exceptions
export const toggleConfigPresetTypes = (selection: ConfigPresetSelection, types: ReadonlyArray<{ readonly key: string }>, checked: boolean): ConfigPresetSelection => {
  return { ...selection, ...Object.fromEntries(types.map((type) => [type.key, checked ? ALL : NONE])) };
};

export const clearConfigPresetTypeSelection = (selection: ConfigPresetSelection, typeKey: string): ConfigPresetSelection => {
  return { ...selection, [typeKey]: NONE };
};

export const toggleConfigPresetItem = (selection: ConfigPresetSelection, typeKey: string, itemKey: string, checked: boolean): ConfigPresetSelection => {
  const { mode, ids } = typeSelection(selection, typeKey);
  const others = ids.filter((id) => id !== itemKey);
  // In 'all' mode the ids are the keys of the excluded items, in 'some' mode the selected ones
  const listed = mode === 'all' ? !checked : checked;
  return { ...selection, [typeKey]: { mode, ids: listed ? [...others, itemKey] : others } };
};

// Keys and excluded keys (ids and excludedIds) of the items query for a filter of the sub-view
export const buildConfigPresetItemsFilter = (
  selection: ConfigPresetSelection,
  forced: ConfigPresetForcedItems,
  typeKey: string,
  filter: ConfigPresetItemsFilter,
): { ids?: readonly string[]; excludedIds?: readonly string[] } => {
  if (filter === 'all') {
    return {};
  }
  const { mode, ids } = typeSelection(selection, typeKey);
  const forcedIds = forced[typeKey] ?? [];
  const selectedIds = [...new Set([...ids, ...forcedIds])];
  const excludedIds = ids.filter((id) => !forcedIds.includes(id));
  if (mode === 'all') {
    return filter === 'selected' ? { excludedIds } : { ids: excludedIds };
  }
  return filter === 'selected' ? { ids: selectedIds } : { excludedIds: selectedIds };
};

// Mutation input, in the order of the types, without empty types; the backend adds the forced items itself
// importModes: what the import does with the items that exist, by item (import only)
// forced: a type with nothing selected is still sent when a forced item of it has a mode, so that the item is imported with it
export const buildConfigPresetSelections = (
  types: ReadonlyArray<CountedType>,
  selection: ConfigPresetSelection,
  importModes: Readonly<Record<string, ConfigImportMode>> = {},
  forced: ConfigPresetForcedItems = {},
) => {
  return types.flatMap((type): ConfigPresetSelectionInput[] => {
    const { mode, ids } = typeSelection(selection, type.key);
    const itemModes = toItemModes(importModes, type.key);
    const withMode = (input: ConfigPresetSelectionInput): ConfigPresetSelectionInput => (itemModes.length > 0 ? { ...input, item_modes: itemModes } : input);
    // Nothing of the type is selected: only the modes of its forced items are kept, never the ones of an item that is not imported
    const forcedModes = itemModes.filter(({ key }) => forced[type.key]?.includes(key));
    const forcedOnly = (): ConfigPresetSelectionInput[] => (forcedModes.length > 0 ? [{ type: type.key, items: [], item_modes: forcedModes }] : []);
    if (mode === 'all') {
      if (ids.length >= type.itemsPageInfo.globalCount) {
        return forcedOnly();
      }
      return [withMode(ids.length > 0 ? { type: type.key, items: null, excluded_items: [...ids] } : { type: type.key, items: null })];
    }
    return ids.length > 0 ? [withMode({ type: type.key, items: [...ids] })] : forcedOnly();
  });
};
