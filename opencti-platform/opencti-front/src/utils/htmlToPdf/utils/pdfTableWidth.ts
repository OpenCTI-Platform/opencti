import { CustomTableLayout } from 'pdfmake/interfaces';
import { detectLanguage } from './pdfFonts';

export const WIDE_TABLE_COLUMN_THRESHOLD = 8;
export const VERY_WIDE_TABLE_COLUMN_THRESHOLD = 12;

const TABLE_PADDING = 10;
const TABLE_BORDER = 1;

const getTableCells = (table: HTMLTableElement) => {
  const occupiedUntil: number[] = [];
  return Array.from(table.rows).flatMap((row, rowIndex) => {
    let column = 0;
    return Array.from(row.cells).map((cell) => {
      while (occupiedUntil[column] > rowIndex) column += 1;
      const position = { cell, column };
      const remainingRows = (row.parentElement?.children.length ?? 1) - row.sectionRowIndex;
      const rowSpan = cell.rowSpan === 0 ? remainingRows : Math.min(cell.rowSpan, remainingRows);
      for (let offset = 0; offset < cell.colSpan; offset += 1) {
        occupiedUntil[column + offset] = rowIndex + rowSpan;
      }
      column += cell.colSpan;
      return position;
    });
  });
};

const getTableColumnCount = (table: HTMLTableElement) => getTableCells(table)
  .reduce((maxColumns, { cell, column }) => Math.max(maxColumns, column + cell.colSpan), 0);

const getColumnMinimumWidths = (table: HTMLTableElement): number[] => {
  const columnCount = getTableColumnCount(table);
  const padding = columnCount >= VERY_WIDE_TABLE_COLUMN_THRESHOLD ? 1 : columnCount >= WIDE_TABLE_COLUMN_THRESHOLD ? 2 : TABLE_PADDING;
  const fontSize = columnCount >= VERY_WIDE_TABLE_COLUMN_THRESHOLD ? 8 : columnCount >= WIDE_TABLE_COLUMN_THRESHOLD ? 9 : 12;
  const spacing = 2 * padding + 2 * TABLE_BORDER;
  const minimums = Array<number>(columnCount).fill(spacing + fontSize);
  getTableCells(table).forEach(({ cell, column }) => {
    const nestedTables = Array.from(cell.querySelectorAll('table')).filter((nested) => nested.parentElement?.closest('table') === table);
    nestedTables.forEach((nested) => {
      const nestedWidth = getColumnMinimumWidths(nested).reduce((total, width) => total + width, 0);
      for (let offset = 0; offset < cell.colSpan; offset += 1) {
        minimums[column + offset] = Math.max(minimums[column + offset], (nestedWidth + spacing) / cell.colSpan);
      }
    });
  });
  return minimums;
};

const allocateColumnWidths = (
  table: HTMLTableElement,
  columnCount: number,
  tableWidth: number,
  padding: number,
  fontSize: number,
  fontFamily: string,
  context: CanvasRenderingContext2D | null,
) => {
  const equalWidth = tableWidth / columnCount;
  if (!context) return Array<number>(columnCount).fill(equalWidth);

  const spacing = 2 * padding + 2 * TABLE_BORDER;
  const minimum = Math.min(equalWidth / 2, spacing + 4 * fontSize);
  const maximum = tableWidth * Math.max(1 / columnCount, Math.min(0.6, 2 / columnCount));
  const desired = Array<number>(columnCount).fill(minimum);
  getTableCells(table).forEach(({ cell, column }) => {
    context.font = `${cell.tagName === 'TH' ? 'bold ' : ''}${fontSize}pt ${fontFamily}`;
    const text = (cell.textContent ?? '').replace(/\s+/g, ' ').trim();
    const textWidth = context.measureText(text).width * 0.75;
    const demand = (textWidth + spacing) / cell.colSpan;
    for (let offset = 0; offset < cell.colSpan; offset += 1) {
      desired[column + offset] = Math.max(desired[column + offset], demand);
    }
  });

  const widths = getColumnMinimumWidths(table).map((width) => Math.max(minimum, width));
  let remaining = tableWidth - widths.reduce((total, width) => total + width, 0);
  if (remaining < 0) return Array<number>(columnCount).fill(equalWidth);
  const maximums = widths.map((width) => Math.max(maximum, width));
  while (remaining > 0.01) {
    const needs = desired.map((width, column) => (
      widths[column] < maximums[column] - 0.01 ? Math.max(0, width - widths[column]) : 0
    ));
    const totalWeight = needs.reduce((total, need) => total + Math.sqrt(need), 0);
    if (totalWeight === 0) break;
    const additions = needs.map((need, column) => Math.min(need, maximums[column] - widths[column], remaining * Math.sqrt(need) / totalWeight));
    additions.forEach((addition, column) => {
      widths[column] += addition;
    });
    remaining -= additions.reduce((total, addition) => total + addition, 0);
  }
  while (remaining > 0.01) {
    const availableColumns = widths.filter((width, column) => width < maximums[column] - 0.01).length;
    if (!availableColumns) break;
    const share = remaining / availableColumns;
    widths.forEach((width, column) => {
      const addition = Math.min(share, Math.max(0, maximums[column] - width));
      widths[column] += addition;
      remaining -= addition;
    });
  }
  const total = widths.reduce((sum, width) => sum + width, 0);
  return widths.map((width) => width * tableWidth / total);
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
  const context = container.querySelector('table') ? document.createElement('canvas').getContext('2d') : null;
  const fontFamily = detectLanguage(content);
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
      const padding = isVeryWideTable ? 1 : isWideTable ? 2 : TABLE_PADDING;
      const parentCell = table.parentElement?.closest('td, th');
      const tableWidth = (parentCell && cellWidths.get(parentCell)) || contentWidth;
      const widths = allocateColumnWidths(table, nbColumns, tableWidth, padding, fontSize ?? 12, fontFamily, context);
      table.setAttribute('data-pdfmake', JSON.stringify({
        layout,
        widths: widths.map((width) => `${100 * width / tableWidth}%`),
        ...(isWideTable ? { fontSize, noWrap: false } : {}),
      }));
      getTableCells(table).forEach(({ cell, column }) => {
        const allocatedWidth = widths.slice(column, column + cell.colSpan).reduce((total, width) => total + width, 0);
        const cellWidth = Math.max(1, allocatedWidth - 2 * padding - 2 * TABLE_BORDER);
        cellWidths.set(cell, cellWidth);
        cell.querySelectorAll('img').forEach((image) => {
          if (image.closest('td, th') === cell) image.style.maxWidth = `${cellWidth}pt`;
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
