export interface ColumnDefinition {
  id: string;
  label: string;
  visible: boolean;
  order: number;
  required?: boolean;
}

export const DEFAULT_COLUMNS: ColumnDefinition[] = [
  { id: 'title', label: 'Title', visible: true, order: 0, required: true },
  { id: 'entityType', label: 'Entity Type', visible: true, order: 1 },
  { id: 'tags', label: 'Tags', visible: true, order: 2 },
  { id: 'updated', label: 'Updated', visible: true, order: 3 },
  { id: 'created', label: 'Created', visible: true, order: 4 },
];

export const COLUMNS_STORAGE_KEY = 'ressa_search_columns';

const normalizeColumns = (stored: ColumnDefinition[]): ColumnDefinition[] => {
  const storedById = new Map(stored.map((column) => [column.id, column]));

  return DEFAULT_COLUMNS
    .map((defaultColumn) => {
      const storedColumn = storedById.get(defaultColumn.id);
      if (!storedColumn) {
        return defaultColumn;
      }

      return {
        ...defaultColumn,
        visible: defaultColumn.required ? true : storedColumn.visible,
        order: storedColumn.order ?? defaultColumn.order,
      };
    })
    .sort((a, b) => a.order - b.order)
    .map((column, index) => ({ ...column, order: index }));
};

export const loadColumnsFromStorage = (): ColumnDefinition[] => {
  try {
    const raw = localStorage.getItem(COLUMNS_STORAGE_KEY);
    if (!raw) {
      return DEFAULT_COLUMNS;
    }

    const parsed = JSON.parse(raw) as ColumnDefinition[];
    if (!Array.isArray(parsed)) {
      return DEFAULT_COLUMNS;
    }

    return normalizeColumns(parsed);
  } catch {
    return DEFAULT_COLUMNS;
  }
};

export const saveColumnsToStorage = (columns: ColumnDefinition[]): void => {
  try {
    localStorage.setItem(COLUMNS_STORAGE_KEY, JSON.stringify(columns));
  } catch {
    // Ignore quota or private mode errors
  }
};
