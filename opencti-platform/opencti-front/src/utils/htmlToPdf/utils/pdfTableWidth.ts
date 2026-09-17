import { CustomTableLayout } from 'pdfmake/interfaces';

export const WIDE_TABLE_COLUMN_THRESHOLD = 8;
export const VERY_WIDE_TABLE_COLUMN_THRESHOLD = 12;

const TABLE_PADDING = 10;
const TABLE_BORDER = 1;

const getTableColumnCount = (table: HTMLTableElement) => {
  const firstRow = table.rows[0];
  return firstRow ? Array.from(firstRow.cells).reduce((total, cell) => total + cell.colSpan, 0) : 0;
};

/**
 * Take tables and add an attribute to make them full width in PDF.
 *
 * @param content The html content in string.
 * @returns Same content but with new attribute on tables.
 */
const setTableFullWidth = (content: string, contentWidth = 515.28) => {
  const container = document.createElement('div');
  container.innerHTML = content;
  const cellWidths = new WeakMap<Element, number>();
  container.querySelectorAll('table').forEach((table) => {
    const nbColumns = getTableColumnCount(table);
    if (nbColumns) {
      const isWideTable = nbColumns >= WIDE_TABLE_COLUMN_THRESHOLD;
      const isVeryWideTable = nbColumns >= VERY_WIDE_TABLE_COLUMN_THRESHOLD;
      let layout: 'default' | 'compact' | 'ultraCompact' = 'default';
      let fontSize: number | undefined;
      if (isVeryWideTable) {
        layout = 'ultraCompact';
        fontSize = 8;
      } else if (isWideTable) {
        layout = 'compact';
        fontSize = 9;
      }
      if (fontSize !== undefined) table.style.fontSize = `${fontSize}pt`;
      table.setAttribute('data-pdfmake', JSON.stringify({
        layout,
        widths: Array(nbColumns).fill(`${100 / nbColumns}%`),
        ...(isWideTable ? { fontSize, noWrap: false } : {}),
      }));
      const padding = isVeryWideTable ? 1 : isWideTable ? 2 : TABLE_PADDING;
      const parentCell = table.parentElement?.closest('td, th');
      const tableWidth = (parentCell && cellWidths.get(parentCell)) || contentWidth;
      Array.from(table.rows).forEach((row) => {
        Array.from(row.cells).forEach((cell) => {
          const cellWidth = Math.max(1, tableWidth * cell.colSpan / nbColumns - 2 * padding - 2 * TABLE_BORDER);
          cellWidths.set(cell, cellWidth);
          cell.querySelectorAll('img').forEach((image) => {
            if (image.closest('td, th') === cell) image.style.maxWidth = `${cellWidth}pt`;
          });
        });
      });
    }
  });
  return container.innerHTML;
};

export const getMaxTableColumnCount = (content: string) => {
  const container = document.createElement('div');
  container.innerHTML = content;
  return Array.from(container.querySelectorAll('table')).reduce((max, table) => {
    const nbColumns = getTableColumnCount(table);
    return Math.max(max, nbColumns);
  }, 0);
};

export const hasWideTable = (content: string) => {
  return getMaxTableColumnCount(content) >= WIDE_TABLE_COLUMN_THRESHOLD;
};

const commonTableLayout: Omit<
  CustomTableLayout,
'paddingBottom' | 'paddingTop' | 'paddingLeft' | 'paddingRight'
> = {
  hLineColor: '#dcdde4',
  vLineColor: '#dcdde4',
  hLineWidth: () => 1,
  vLineWidth: (i, { table }) => ((i === 0 || i === (table.widths ?? []).length) ? TABLE_BORDER : 0),
};

const createTableLayout = (padding: number): CustomTableLayout => ({
  ...commonTableLayout,
  paddingBottom: () => padding,
  paddingTop: () => padding,
  paddingLeft: () => padding,
  paddingRight: () => padding,
});

export const defaultTableLayout: { [p: string]: CustomTableLayout } = {
  default: {
    ...createTableLayout(4),
    paddingLeft: () => TABLE_PADDING,
    paddingRight: () => TABLE_PADDING,
  },
  compact: createTableLayout(2),
  ultraCompact: createTableLayout(1),
};

export default setTableFullWidth;
