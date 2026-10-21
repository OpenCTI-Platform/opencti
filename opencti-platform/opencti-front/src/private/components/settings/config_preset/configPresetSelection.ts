// Checked item keys, by exportable type key
export type ConfigPresetSelection = Record<string, readonly string[]>;

interface ExportableType {
  readonly key: string;
  readonly items: ReadonlyArray<{ readonly key: string }>;
}

// The export groups of the catalog, in catalog order, each with its types
export const groupConfigPresetTypes = <T extends ExportableType & { readonly group: { readonly key: string; readonly label: string } }>(
  types: ReadonlyArray<T>,
) => {
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
export const isSingletonConfigPresetType = (type: ExportableType): boolean => {
  return type.items.length === 1 && type.items[0].key === type.key;
};

export const selectAllConfigPresetItems = (types: ReadonlyArray<ExportableType>): ConfigPresetSelection => {
  return Object.fromEntries(types.map((type) => [type.key, type.items.map((item) => item.key)]));
};

export const countConfigPresetItems = (types: ReadonlyArray<ExportableType>): number => {
  return types.reduce((count, type) => count + type.items.length, 0);
};

export const countConfigPresetCheckedItems = (types: ReadonlyArray<ExportableType>, selection: ConfigPresetSelection): number => {
  return types.reduce((count, type) => count + type.items.filter((item) => selection[type.key]?.includes(item.key)).length, 0);
};

// State of the checkbox of a type or a group: checked when all its items are, indeterminate when only some are
export const getConfigPresetCheckboxState = (types: ReadonlyArray<ExportableType>, selection: ConfigPresetSelection): boolean | 'indeterminate' => {
  const checkedCount = countConfigPresetCheckedItems(types, selection);
  if (checkedCount === 0) {
    return false;
  }
  return checkedCount === countConfigPresetItems(types) ? true : 'indeterminate';
};

export const toggleConfigPresetTypes = (selection: ConfigPresetSelection, types: ReadonlyArray<ExportableType>, checked: boolean): ConfigPresetSelection => {
  return { ...selection, ...Object.fromEntries(types.map((type) => [type.key, checked ? type.items.map((item) => item.key) : []])) };
};

export const toggleConfigPresetItem = (
  selection: ConfigPresetSelection,
  typeKey: string,
  itemKey: string,
  checked: boolean,
): ConfigPresetSelection => {
  const current = (selection[typeKey] ?? []).filter((key) => key !== itemKey);
  return { ...selection, [typeKey]: checked ? [...current, itemKey] : current };
};

// Mutation input: the checked items of each type, in catalog order, without empty types.
// The items are always listed explicitly (never `items: null`, "every item at export time"), so that
// the export matches what was shown in the drawer even if an item is created while it is open.
export const buildConfigPresetSelections = (types: ReadonlyArray<ExportableType>, selection: ConfigPresetSelection) => {
  return types
    .map((type) => ({ type: type.key, items: type.items.map((item) => item.key).filter((key) => selection[type.key]?.includes(key)) }))
    .filter(({ items }) => items.length > 0);
};
