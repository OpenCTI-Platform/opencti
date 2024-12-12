import { CustomTableLayout } from 'pdfmake/interfaces';

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
    const header = table.querySelector('thead tr');
    const body = table.querySelector('tbody tr');
    const element = header ?? body;
    if (element) {
      const nbColumns = element.querySelectorAll(header ? 'th' : 'td').length;
      if (nbColumns) {
        table.setAttribute('data-pdfmake', `{'layout':'default', 'widths':[${Array(nbColumns).fill("'*'").join()}]}`);
      }
    }
  });
  return container.innerHTML;
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
};

export default setTableFullWidth;
