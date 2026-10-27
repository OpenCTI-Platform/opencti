import type { ConfigPresetSelection } from './configPresetSelection';

interface ImportType {
  readonly key: string;
  readonly items: ReadonlyArray<{ readonly key: string; readonly requiresEnterpriseEdition: boolean }>;
}

interface ImportSelectionInput {
  type: string;
  items: string[] | null;
  excluded_items?: string[];
}

// The keys of the items that need the Enterprise Edition, by type key
export const getEnterpriseEditionKeys = (types: ReadonlyArray<ImportType>): Record<string, string[]> => {
  return Object.fromEntries(types.map((type) => [type.key, type.items.filter((item) => item.requiresEnterpriseEdition).map((item) => item.key)]));
};

// On a Community platform the items that need the Enterprise Edition are left out of what the selection helpers see: "select all",
// the checkboxes of a type and the counts only see the other items. With the Enterprise Edition nothing is left out.
export const withoutEnterpriseEditionItems = <T extends ImportType>(types: ReadonlyArray<T>, isEnterpriseEdition: boolean): T[] => {
  return types.map((type) => (isEnterpriseEdition ? type : { ...type, items: type.items.filter((item) => !item.requiresEnterpriseEdition) }));
};

// A selection restored from the session drops the items that need the Enterprise Edition while on a Community platform
// (the license may have expired between two visits)
export const dropEnterpriseEditionItems = (selection: ConfigPresetSelection, eeKeys: Record<string, string[]>): ConfigPresetSelection => {
  return Object.fromEntries(Object.entries(selection).map(([typeKey, { mode, ids }]) => [
    typeKey,
    mode === 'some' ? { mode, ids: ids.filter((id) => !(eeKeys[typeKey] ?? []).includes(id)) } : { mode, ids },
  ]));
};

// Items that were unselectable are not ticked by a license: a type in 'all' mode excludes them, a type in 'some' mode needs nothing
export const excludeEnterpriseEditionItems = (selection: ConfigPresetSelection, eeKeys: Record<string, string[]>): ConfigPresetSelection => {
  return Object.fromEntries(Object.entries(selection).map(([typeKey, { mode, ids }]) => [
    typeKey,
    mode === 'all' ? { mode, ids: [...new Set([...ids, ...(eeKeys[typeKey] ?? [])])] } : { mode, ids },
  ]));
};

// The mutation input on a Community platform: the keys of the items that need the Enterprise Edition are added to the excluded
// items of each type sent in "all" mode, so that the backend never receives them
export const addEnterpriseEditionExclusions = <T extends ImportSelectionInput>(selections: T[], eeKeys: Record<string, string[]>): T[] => {
  return selections.map((selection) => {
    const keys = eeKeys[selection.type] ?? [];
    if (selection.items !== null || keys.length === 0) {
      return selection;
    }
    return { ...selection, excluded_items: [...new Set([...(selection.excluded_items ?? []), ...keys])] };
  });
};
