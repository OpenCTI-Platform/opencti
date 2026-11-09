import type { DataTableColumn, DataTableColumns, LocalStorageColumns } from './dataTableTypes';

// Columns that are not attributes of the listed entities: they are never configurable.
export const TECHNICAL_COLUMN_IDS = ['select', 'navigate', 'icon'];

export const isDataColumn = ({ id }: Pick<DataTableColumn, 'id'>) => !TECHNICAL_COLUMN_IDS.includes(id);

// Displayed columns of a list, in their order. A hidden column keeps its place so that it can be shown again.
export type ListColumnConfig = { id: string; visible: boolean; percentWidth: number };

// Saved in the user profile (list_columns), keyed by the storage key of each list.
export type ListColumnsConfig = Record<string, ListColumnConfig[]>;

export const parseListColumnsConfig = (value?: string | null): ListColumnsConfig => {
  if (!value) return {};
  try {
    const parsed = JSON.parse(value);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
};

const roundWidth = (percentWidth: number) => Math.round(percentWidth * 100) / 100;

export const toListColumnConfig = (columns: DataTableColumns): ListColumnConfig[] => columns
  .filter(isDataColumn)
  .map(({ id, visible, percentWidth }) => ({ id, visible: visible ?? true, percentWidth: roundWidth(percentWidth ?? 0) }));

export const isSameListColumnConfig = (a?: ListColumnConfig[], b?: ListColumnConfig[]) => JSON.stringify(a ?? []) === JSON.stringify(b ?? []);

// Configuration stored in the browser before it was saved in the user profile.
// As before, it is only kept while the list still has the same default columns, in the same order.
export const legacyListColumnConfig = (
  localStorageColumns: LocalStorageColumns,
  defaultColumnIds: string[],
): ListColumnConfig[] | undefined => {
  const entries = Object.entries(localStorageColumns).filter(([id]) => !TECHNICAL_COLUMN_IDS.includes(id));
  const isOrderSame = entries.length === defaultColumnIds.length && entries.every(([id], index) => id === defaultColumnIds[index]);
  if (!isOrderSame) return undefined;
  return entries
    .map(([id, column], index) => ({ id, column, order: column.index ?? index }))
    .sort((a, b) => a.order - b.order)
    .map(({ id, column }) => ({ id, visible: column.visible ?? true, percentWidth: roundWidth(column.percentWidth) }));
};

// Width of each visible column in px. Columns are sized in percent of the table: when the visible ones
// take less than the table width (some are hidden), they are enlarged to fill it, without a gap at the end.
// When they take more, the table scrolls horizontally.
export const computeVisibleWidthRatio = (columns: DataTableColumns) => {
  const visiblePercent = columns
    .filter((column) => isDataColumn(column) && column.visible)
    .reduce((acc, column) => acc + (column.percentWidth ?? 0), 0);
  return visiblePercent > 0 && visiblePercent < 100 ? 100 / visiblePercent : 1;
};
