// Checked item ids, by exportable type id
export type ConfigPresetSelection = Record<string, readonly string[]>;

interface ExportableType {
  readonly id: string;
  readonly items: ReadonlyArray<{ readonly id: string }>;
}

// The export groups of the catalog, in catalog order, each with its types
export const groupConfigPresetTypes = <T extends ExportableType & { readonly group: { readonly id: string; readonly label: string } }>(
  types: ReadonlyArray<T>,
) => {
  const groups: { id: string; label: string; types: T[] }[] = [];
  types.forEach((type) => {
    const group = groups.find(({ id }) => id === type.group.id);
    if (group) {
      group.types.push(type);
    } else {
      groups.push({ id: type.group.id, label: type.group.label, types: [type] });
    }
  });
  return groups;
};

// A singleton type has one item with the id of the type: it is shown as a single checkbox
export const isSingletonConfigPresetType = (type: ExportableType): boolean => {
  return type.items.length === 1 && type.items[0].id === type.id;
};

export const selectAllConfigPresetItems = (types: ReadonlyArray<ExportableType>): ConfigPresetSelection => {
  return Object.fromEntries(types.map((type) => [type.id, type.items.map((item) => item.id)]));
};

export const countConfigPresetItems = (types: ReadonlyArray<ExportableType>): number => {
  return types.reduce((count, type) => count + type.items.length, 0);
};

export const countConfigPresetCheckedItems = (types: ReadonlyArray<ExportableType>, selection: ConfigPresetSelection): number => {
  return types.reduce((count, type) => count + type.items.filter((item) => selection[type.id]?.includes(item.id)).length, 0);
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
  return { ...selection, ...Object.fromEntries(types.map((type) => [type.id, checked ? type.items.map((item) => item.id) : []])) };
};

export const toggleConfigPresetItem = (
  selection: ConfigPresetSelection,
  typeId: string,
  itemId: string,
  checked: boolean,
): ConfigPresetSelection => {
  const current = (selection[typeId] ?? []).filter((id) => id !== itemId);
  return { ...selection, [typeId]: checked ? [...current, itemId] : current };
};

// Mutation input: the checked items of each type, in catalog order, without empty types
export const buildConfigPresetSelections = (types: ReadonlyArray<ExportableType>, selection: ConfigPresetSelection) => {
  return types
    .map((type) => ({ type: type.id, items: type.items.map((item) => item.id).filter((id) => selection[type.id]?.includes(id)) }))
    .filter(({ items }) => items.length > 0);
};
