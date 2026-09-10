import { describe, expect, it } from 'vitest';
import setTableFullWidth, { getMaxTableColumnCount, hasWideTable } from './pdfTableWidth';

describe('Utils: setTableFullWidth', () => {
  it('uses compact layout and smaller font for wide tables', () => {
    const columns = Array.from({ length: 8 }, (_, i) => `<th>h${i}</th>`).join('');
    const html = `<table><thead><tr>${columns}</tr></thead><tbody><tr>${Array.from({ length: 8 }, () => '<td>v</td>').join('')}</tr></tbody></table>`;

    const result = setTableFullWidth(html);
    const container = document.createElement('div');
    container.innerHTML = result;
    const pdfMakeAttr = container.querySelector('table')?.getAttribute('data-pdfmake') ?? '';

    expect(pdfMakeAttr).toContain("'layout':'compact'");
    expect(pdfMakeAttr).toContain("'fontSize':9");
  });

  it('uses default layout for regular tables', () => {
    const columns = Array.from({ length: 3 }, (_, i) => `<th>h${i}</th>`).join('');
    const html = `<table><thead><tr>${columns}</tr></thead></table>`;

    const result = setTableFullWidth(html);
    const container = document.createElement('div');
    container.innerHTML = result;
    const pdfMakeAttr = container.querySelector('table')?.getAttribute('data-pdfmake') ?? '';

    expect(pdfMakeAttr).toContain("'layout':'default'");
    expect(pdfMakeAttr).not.toContain("'fontSize':9");
  });

  it('detects wide tables', () => {
    const wideColumns = Array.from({ length: 8 }, (_, i) => `<th>h${i}</th>`).join('');
    const narrowColumns = Array.from({ length: 3 }, (_, i) => `<th>h${i}</th>`).join('');
    const wideHtml = `<table><thead><tr>${wideColumns}</tr></thead></table>`;
    const narrowHtml = `<table><thead><tr>${narrowColumns}</tr></thead></table>`;

    expect(hasWideTable(wideHtml)).toBe(true);
    expect(hasWideTable(narrowHtml)).toBe(false);
  });

  it('uses ultra compact layout for very wide tables', () => {
    const columns = Array.from({ length: 12 }, (_, i) => `<th>h${i}</th>`).join('');
    const html = `<table><thead><tr>${columns}</tr></thead></table>`;
    const result = setTableFullWidth(html);
    const container = document.createElement('div');
    container.innerHTML = result;
    const pdfMakeAttr = container.querySelector('table')?.getAttribute('data-pdfmake') ?? '';

    expect(pdfMakeAttr).toContain("'layout':'ultraCompact'");
    expect(pdfMakeAttr).toContain("'fontSize':8");
  });

  it('returns max number of columns among all tables', () => {
    const table3 = `<table><thead><tr>${Array.from({ length: 3 }, (_, i) => `<th>a${i}</th>`).join('')}</tr></thead></table>`;
    const table11 = `<table><thead><tr>${Array.from({ length: 11 }, (_, i) => `<th>b${i}</th>`).join('')}</tr></thead></table>`;
    const html = `${table3}${table11}`;
    expect(getMaxTableColumnCount(html)).toBe(11);
  });
});
