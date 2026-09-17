import { describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import htmlToPdfmake from 'html-to-pdfmake';
import pdfMake from 'pdfmake/build/pdfmake';
import fonts from 'pdfmake/build/vfs_fonts';
import { getDocument, OPS, Util } from 'pdfjs-dist/legacy/build/pdf.mjs';
import setTableFullWidth, { defaultTableLayout, getMaxTableColumnCount, hasWideTable } from './pdfTableWidth';
import { htmlToPdf, htmlToPdfReport } from '../htmlToPdf';

describe('Utils: setTableFullWidth', () => {
  it('uses compact layout and smaller font for wide tables', () => {
    const columns = Array.from({ length: 8 }, (_, i) => `<th>h${i}</th>`).join('');
    const html = `<table><thead><tr>${columns}</tr></thead><tbody><tr>${Array.from({ length: 8 }, () => '<td>v</td>').join('')}</tr></tbody></table>`;

    const result = setTableFullWidth(html);
    const container = document.createElement('div');
    container.innerHTML = result;
    const pdfMakeAttr = container.querySelector('table')?.getAttribute('data-pdfmake') ?? '';

    expect(JSON.parse(pdfMakeAttr)).toMatchObject({ layout: 'compact', fontSize: 9, noWrap: false });
  });

  it('uses default layout for regular tables', () => {
    const columns = Array.from({ length: 3 }, (_, i) => `<th>h${i}</th>`).join('');
    const html = `<table><thead><tr>${columns}</tr></thead></table>`;

    const result = setTableFullWidth(html);
    const container = document.createElement('div');
    container.innerHTML = result;
    const pdfMakeAttr = container.querySelector('table')?.getAttribute('data-pdfmake') ?? '';

    expect(JSON.parse(pdfMakeAttr)).toMatchObject({ layout: 'default' });
    expect(JSON.parse(pdfMakeAttr)).not.toHaveProperty('fontSize');
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

    expect(JSON.parse(pdfMakeAttr)).toMatchObject({ layout: 'ultraCompact', fontSize: 8, noWrap: false });
  });

  it('returns max number of columns among all tables', () => {
    const table3 = `<table><thead><tr>${Array.from({ length: 3 }, (_, i) => `<th>a${i}</th>`).join('')}</tr></thead></table>`;
    const table11 = `<table><thead><tr>${Array.from({ length: 11 }, (_, i) => `<th>b${i}</th>`).join('')}</tr></thead></table>`;
    const html = `${table3}${table11}`;
    expect(getMaxTableColumnCount(html)).toBe(11);
  });
});

vi.mock('./pdfFonts', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./pdfFonts')>();
  const localFont = {
    normal: 'Roboto-Regular.ttf',
    bold: 'Roboto-Medium.ttf',
    italics: 'Roboto-Italic.ttf',
    bolditalics: 'Roboto-MediumItalic.ttf',
  };
  return { ...actual, FONTS: { Roboto: localFont, Geologica: localFont } };
});

vi.mock('../../Image', () => ({ getBase64ImageFromURL: async () => '' }));

describe('PDF table layout', () => {
  const hash = '0123456789abcdef'.repeat(4);
  const url = `https://example.com/${hash}`;
  const imageData = readFileSync('src/static/images/logo_text_white.png');
  const image = `<img src="data:image/png;base64,${imageData.toString('base64')}" width="300">`;
  const cases = [
    { name: 'prose', value: 'Normal words remain readable' },
    { name: 'hash', value: hash },
    { name: 'URL', value: url },
  ];

  const exportCases = ['table helper', 'HTML', 'Markdown', 'Fintel'].flatMap((exportType) => (
    exportType === 'Markdown'
      ? [{ exportType, spanningHeader: false }]
      : [{ exportType, spanningHeader: false }, { exportType, spanningHeader: true }]
  )).flatMap((exportCase) => [4, 8, 12].map((columnCount) => ({ ...exportCase, columnCount })));

  it.each(exportCases)('keeps complete text within margins for $exportType exports ($columnCount columns, merged header: $spanningHeader)', async ({ exportType, spanningHeader, columnCount }) => {
    pdfMake.addVirtualFileSystem(fonts);
    pdfMake.setTableLayouts(defaultTableLayout);
    const extraHeaders = Array(columnCount - 4).fill('Extra');
    const extraCells = Array(columnCount - 4).fill('Data');
    const headers = ['Name', 'Value', 'Description', ...extraHeaders, 'Status'];
    const heading = spanningHeader ? `<tr><th colspan="${columnCount}">Merged header</th></tr>` : '';
    const rows = cases.map(({ name, value }) => [name, value === url ? `<a href="${url}">${value}</a>` : value, 'Normal words remain readable', ...extraCells, 'Last column']);
    rows.push(['Image', '', '', ...extraCells, image]);
    const html = `<table><thead>${heading}<tr>${headers.map((header) => `<th>${header}</th>`).join('')}</tr></thead><tbody>${rows.map((row) => `<tr>${row.map((cell) => `<td>${cell}</td>`).join('')}</tr>`).join('')}</tbody></table>`;
    const markdown = `| ${headers.join(' | ')} |\n| ${Array(columnCount).fill('---').join(' | ')} |\n${rows.map((row) => `| ${row.join(' | ')} |`).join('\n')}`;
    const pdf = exportType === 'table helper'
      ? pdfMake.createPdf({ content: htmlToPdfmake(setTableFullWidth(html)), pageMargins: [40, 40, 40, 40] })
      : exportType === 'Fintel'
        ? await htmlToPdfReport('Report', html, 'Template', [], null, { includeCoverPage: false, includeBackPage: false })
        : htmlToPdf(exportType === 'Markdown' ? 'report.md' : 'report.html', exportType === 'Markdown' ? markdown : html);
    const buffer = await pdf.getBuffer();
    const document = await getDocument({ data: new Uint8Array(buffer) }).promise;
    try {
      expect(document.numPages).toBe(1);
      const page = await document.getPage(1);
      const isWideFintel = exportType === 'Fintel' && columnCount >= 8;
      const isVeryWideFintel = exportType === 'Fintel' && columnCount >= 12;
      const pageWidth = isVeryWideFintel ? 1190.55 : isWideFintel ? 841.89 : 595.28;
      const pageHeight = isVeryWideFintel ? 841.89 : isWideFintel ? 595.28 : 841.89;
      expect(page.getViewport({ scale: 1 }).width).toBeCloseTo(pageWidth, 2);
      expect(page.getViewport({ scale: 1 }).height).toBeCloseTo(pageHeight, 2);
      const content = await page.getTextContent();
      const textItems = content.items.filter((item) => 'str' in item);
      expect(textItems.map((item) => item.str).join(' ').replace(/\s+/g, ' ')).toContain('Last column');
      const compactText = textItems.map((item) => item.str).join('').replace(/\s+/g, '');
      for (const { value } of cases) {
        expect(compactText).toContain(value.replace(/\s+/g, ''));
      }
      expect(textItems.some((item) => item.str.includes('Normal'))).toBe(true);
      const margin = isVeryWideFintel ? 8 : isWideFintel ? 10 : exportType === 'Fintel' ? 20 : 40;
      for (const item of textItems) {
        expect(item.transform[4]).toBeGreaterThanOrEqual(margin - 0.01);
        expect(item.transform[4] + item.width).toBeLessThanOrEqual(pageWidth - margin + 0.01);
      }
      const expectedFontSize = columnCount >= 12 ? 8 : columnCount >= 8 ? 9 : 12;
      expect(textItems.find((item) => item.str === 'Image')?.height).toBeCloseTo(expectedFontSize, 2);
      const annotations = await page.getAnnotations();
      expect(annotations.some((annotation) => annotation.url === url)).toBe(true);
      const operators = await page.getOperatorList();
      const transforms: number[][] = [];
      let transform = [1, 0, 0, 1, 0, 0];
      let imageCount = 0;
      operators.fnArray.forEach((operation, index) => {
        if (operation === OPS.save) transforms.push([...transform]);
        else if (operation === OPS.restore) transform = transforms.pop()!;
        else if (operation === OPS.transform) transform = Util.transform(transform, operators.argsArray[index]);
        else if (operation === OPS.paintImageXObject) {
          imageCount += 1;
          expect(transform[4]).toBeGreaterThanOrEqual(margin);
          expect(transform[4] + transform[0]).toBeLessThanOrEqual(pageWidth - margin + 0.01);
          const padding = columnCount >= 12 ? 1 : columnCount >= 8 ? 2 : 10;
          expect(transform[0]).toBeCloseTo((pageWidth - 2 * margin) / columnCount - 2 * padding - 2, 2);
          expect(Math.abs(transform[0] / transform[3])).toBeCloseTo(imageData.readUInt32BE(16) / imageData.readUInt32BE(20), 2);
        }
      });
      expect(imageCount).toBe(1);
    } finally {
      await document.destroy();
    }
  });
});
