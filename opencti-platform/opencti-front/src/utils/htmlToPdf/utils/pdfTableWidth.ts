import { CustomTableLayout } from 'pdfmake/interfaces';

const WIDE_TABLE_COLUMN_THRESHOLD = 8;
const VERY_WIDE_TABLE_COLUMN_THRESHOLD = 12;

const getTableColumnCount = (table: Element) => {
  const header = table.querySelector('thead tr');
  const body = table.querySelector('tbody tr');
  const element = header ?? body;
  if (!element) return 0;
  return element.querySelectorAll(header ? 'th' : 'td').length;
};

/**
 * Take tables and add an attribute to make them full width in PDF.
 *
 * @param content The html content in string.
 * @returns Same content but with new attribute on tables.
 */
const setTableFullWidth = (content: string) => {
  const container = document.createElement('div');
  container.innerHTML = content;
  container.querySelectorAll('table').forEach((table) => {
    const nbColumns = getTableColumnCount(table);
    if (nbColumns) {
      const isWideTable = nbColumns >= WIDE_TABLE_COLUMN_THRESHOLD;
      const isVeryWideTable = nbColumns >= VERY_WIDE_TABLE_COLUMN_THRESHOLD;
      const layout = isVeryWideTable ? 'ultraCompact' : isWideTable ? 'compact' : 'default';
      const fontSize = isVeryWideTable ? 8 : isWideTable ? 9 : undefined;
      const noWrap = isWideTable ? ', \'noWrap\':false' : '';
      const computedFontSize = typeof fontSize === 'number' ? `, 'fontSize':${fontSize}` : '';
      table.setAttribute(
        'data-pdfmake',
        `{'layout':'${layout}', 'widths':[${Array(nbColumns).fill("'*'").join()}]${computedFontSize}${noWrap}}`,
      );
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

export const defaultTableLayout: { [p: string]: CustomTableLayout } = {
  default: {
    hLineColor: '#dcdde4',
    vLineColor: '#dcdde4',
    paddingBottom: () => 4,
    paddingTop: () => 4,
    paddingLeft: () => 10,
    paddingRight: () => 10,
    hLineWidth: () => 1,
    vLineWidth: (i, { table }) => ((i === 0 || i === (table.widths ?? []).length) ? 1 : 0),
  },
  compact: {
    hLineColor: '#dcdde4',
    vLineColor: '#dcdde4',
    paddingBottom: () => 2,
    paddingTop: () => 2,
    paddingLeft: () => 2,
    paddingRight: () => 2,
    hLineWidth: () => 1,
    vLineWidth: (i, { table }) => ((i === 0 || i === (table.widths ?? []).length) ? 1 : 0),
  },
  ultraCompact: {
    hLineColor: '#dcdde4',
    vLineColor: '#dcdde4',
    paddingBottom: () => 1,
    paddingTop: () => 1,
    paddingLeft: () => 1,
    paddingRight: () => 1,
    hLineWidth: () => 1,
    vLineWidth: (i, { table }) => ((i === 0 || i === (table.widths ?? []).length) ? 1 : 0),
  },
};

export default setTableFullWidth;
