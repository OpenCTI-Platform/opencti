import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import htmlToPdfmake from 'html-to-pdfmake';
import pdfMake from 'pdfmake/build/pdfmake';
import fonts from 'pdfmake/build/vfs_fonts';
// Deliberately not declared: this must stay the copy react-pdf resolves, since pdf.js throws
// when the API and the worker differ in version. The legacy build is the one that runs on Node.
// eslint-disable-next-line import/no-extraneous-dependencies
import { getDocument, OPS, Util } from 'pdfjs-dist/legacy/build/pdf.mjs';
import setTableFullWidth, { defaultTableLayout, getMaxTableColumnCount, hasWideTable } from './pdfTableWidth';
import { htmlToPdf, htmlToPdfReport } from '../htmlToPdf';

beforeAll(async () => {
  pdfMake.addVirtualFileSystem(fonts);
  const cjkFonts = ['NotoSansJP-Regular.ttf', 'NotoSansJP-Bold.ttf', 'NotoSansKR-Regular.ttf', 'NotoSansKR-Bold.ttf'];
  pdfMake.addVirtualFileSystem(Object.fromEntries(cjkFonts.map((name) => [name, readFileSync(`public/assets/static/${name}`).toString('base64')])));
  const pdf = pdfMake.createPdf({ content: '' });
  const stream = await pdf.getStream() as unknown as {
    provideFont: (family: string, bold: boolean, italics: boolean) => {
      widthOfString: (text: string, size: number) => number;
    };
  };
  const measurement = {
    font: '12pt Roboto',
    measureText(text: string) {
      const size = Number(this.font.match(/([\d.]+)pt/)?.[1] ?? 12);
      return { width: stream.provideFont('Roboto', this.font.includes('bold'), false).widthOfString(text, size) / 0.75 };
    },
  };
  vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockReturnValue(measurement as unknown as CanvasRenderingContext2D);
  await pdf.getBuffer();
});

afterAll(() => vi.restoreAllMocks());

describe('Utils: setTableFullWidth', () => {
  const prepareTable = (html: string, contentWidth = 515.28) => {
    const container = document.createElement('div');
    container.innerHTML = setTableFullWidth(html, contentWidth);
    const table = container.querySelector('table')!;
    const definition = JSON.parse(table.getAttribute('data-pdfmake')!);
    const percentages = (definition.widths as string[]).map((width) => Number.parseFloat(width));
    return { table, percentages };
  };

  it('gives longer descriptions more space even when both require wrapping', () => {
    const { percentages } = prepareTable(`<table><tr><td>ID</td><td>${'Description '.repeat(10)}</td><td>${'Description '.repeat(60)}</td></tr></table>`);
    expect(percentages[2]).toBeGreaterThan(percentages[1] + 5);
    expect(percentages.reduce((total, width) => total + width, 0)).toBeCloseTo(100, 8);
  });

  it('measures glyph widths and includes headers in the allocation', () => {
    const { percentages } = prepareTable('<table><tr><th>WWWWWWWW</th><th>iiiiiiii</th></tr><tr><td>1</td><td>1</td></tr></table>');
    expect(percentages[0]).toBeGreaterThan(percentages[1]);
  });

  it.each(['\u65e5\u672c\u8a9e', '\ud55c\uad6d\uc5b4'])('preserves CJK demand when the browser underestimates %s glyphs', (text) => {
    const measurement = { font: '', measureText: () => ({ width: 0 }) };
    vi.mocked(HTMLCanvasElement.prototype.getContext).mockReturnValueOnce(measurement as unknown as CanvasRenderingContext2D);
    const { percentages } = prepareTable(`<table><tr><td>ID</td><td>${text.repeat(10)}</td><td>Status</td></tr></table>`);
    expect(percentages[1]).toBeGreaterThan(percentages[0]);
    expect(percentages[1]).toBeGreaterThan(percentages[2]);
    expect(percentages[1]).toBeLessThanOrEqual(60.01);
    expect(percentages.reduce((total, width) => total + width, 0)).toBeCloseTo(100, 8);
  });

  it.each([1, 2, 4, 8, 12])('keeps balanced content balanced across %i columns', (columnCount) => {
    const { percentages } = prepareTable(`<table><tr>${'<td>Equal content</td>'.repeat(columnCount)}</tr></table>`);
    percentages.forEach((width) => expect(width).toBeCloseTo(100 / columnCount, 8));
  });

  it.each([2, 4, 8, 12])('bounds outlier demand across %i columns', (columnCount) => {
    const { percentages } = prepareTable(`<table><tr><td>${'abcdef0123456789'.repeat(200)}</td>${'<td>ID</td>'.repeat(columnCount - 1)}</tr></table>`);
    expect(percentages.reduce((total, width) => total + width, 0)).toBeCloseTo(100, 8);
    expect(percentages[0]).toBeGreaterThan(100 / columnCount);
    percentages.forEach((width) => {
      expect(width).toBeGreaterThanOrEqual(50 / columnCount - 0.01);
      expect(width).toBeLessThanOrEqual(Math.min(60, 200 / columnCount) + 0.01);
    });
  });

  it('limits images to the sum of their allocated spanned columns', () => {
    const { table, percentages } = prepareTable(`<table><tr><th>ID</th><th>${'Description '.repeat(20)}</th><th>Status</th></tr><tr><td>42</td><td colspan="2"><img src="example.png" width="1000"></td></tr></table>`, 500);
    const imageWidth = Number.parseFloat(table.querySelector('img')!.style.maxWidth);
    expect(imageWidth).toBeCloseTo(500 * (percentages[1] + percentages[2]) / 100 - 22, 8);
  });

  it('assigns images to the correct column after a row-spanning cell', () => {
    const { table, percentages } = prepareTable(`<table><tr><td rowspan="2">${'Description '.repeat(20)}</td><td>Status</td></tr><tr><td><img src="example.png" width="1000"></td></tr></table>`, 500);
    const imageWidth = Number.parseFloat(table.querySelector('img')!.style.maxWidth);
    expect(percentages[0]).toBeGreaterThan(percentages[1]);
    expect(imageWidth).toBeCloseTo(500 * percentages[1] / 100 - 22, 8);
  });

  it.each(['thead', 'tbody'])('clamps rowspans to their %s section before PDF conversion', (section) => {
    const html = `<table><${section}><tr><th rowspan="3">Group</th><th>Heading</th></tr></${section}><tbody><tr><td>A</td><td>B</td></tr></tbody></table>`;
    const { table, percentages } = prepareTable(html);
    expect(getMaxTableColumnCount(html)).toBe(2);
    expect(table.querySelector('th')!.rowSpan).toBe(1);
    const converted = htmlToPdfmake(table.outerHTML) as unknown as { table: { body: unknown[][] } }[];
    expect(converted[0].table.body.map((row) => row.length)).toEqual([2, 2]);
    expect(percentages).toHaveLength(2);
  });

  it('expands rowspan zero to the remaining rows of its section', () => {
    const html = '<table><tbody><tr><td rowspan="0">Group</td><td>A</td></tr><tr><td>B</td></tr></tbody><tbody><tr><td>C</td><td>D</td></tr></tbody></table>';
    const { table } = prepareTable(html);
    expect(table.querySelector('td')!.rowSpan).toBe(2);
    const converted = htmlToPdfmake(table.outerHTML) as unknown as { table: { body: unknown[][] } }[];
    expect(converted[0].table.body.map((row) => row.length)).toEqual([2, 2, 2]);
  });

  it.each(['Data', ''])('reserves space for nested table padding with "%s" cells', (value) => {
    const nested = `<table><tr>${`<td>${value}</td>`.repeat(4)}</tr></table>`;
    const { table, percentages } = prepareTable(`<table><tr><td>${'Description '.repeat(200)}</td><td>ID</td><td>Status</td><td>${nested}</td></tr></table>`);
    const nestedWidth = 515.28 * percentages[3] / 100 - 22;
    const nestedDefinition = JSON.parse(table.querySelector('table')!.getAttribute('data-pdfmake')!);
    nestedDefinition.widths.forEach((width: string) => {
      expect(nestedWidth * Number.parseFloat(width) / 100).toBeGreaterThan(22);
    });
  });

  it('falls back to bounded equal widths without text measurement', () => {
    vi.mocked(HTMLCanvasElement.prototype.getContext).mockReturnValueOnce(null);
    const { percentages } = prepareTable('<table><tr><td>ID</td><td>A longer description</td></tr></table>');
    expect(percentages).toEqual([50, 50]);
  });

  it('scales overflowing minimum widths proportionally for dense nested tables', () => {
    const nested = `<table><tr>${'<td>Data</td>'.repeat(4)}</tr></table>`;
    const { percentages } = prepareTable(`<table><tr><td>${nested}</td><td>ID</td></tr></table>`, 100);
    expect(percentages[0] / percentages[1]).toBeCloseTo((4 * 34 + 22) / 34, 8);
    expect(percentages.reduce((total, width) => total + width, 0)).toBeCloseTo(100, 8);
    percentages.forEach((width) => expect(width).toBeGreaterThan(0));
  });

  it.each([4, 8, 12])('counts %i columns in a body wider than its grouped header', (columnCount) => {
    const cells = Array(columnCount / 2).fill('<td colspan="2">Value</td>').join('');
    const html = `<table><thead><tr><th colspan="2">Group</th></tr></thead><tbody><tr>${cells}</tr></tbody></table>`;
    expect(getMaxTableColumnCount(html)).toBe(columnCount);
    expect(hasWideTable(html)).toBe(columnCount >= 8);
    const container = document.createElement('div');
    container.innerHTML = setTableFullWidth(html);
    const definition = JSON.parse(container.querySelector('table')!.getAttribute('data-pdfmake')!);
    expect(definition.widths).toHaveLength(columnCount);
    expect(definition.layout).toBe(columnCount >= 12 ? 'ultraCompact' : columnCount >= 8 ? 'compact' : 'default');
  });

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
  return {
    ...actual,
    FONTS: {
      Roboto: localFont,
      Geologica: localFont,
      NotoSansJp: { normal: 'NotoSansJP-Regular.ttf', bold: 'NotoSansJP-Bold.ttf' },
      NotoSansKr: { normal: 'NotoSansKR-Regular.ttf', bold: 'NotoSansKR-Bold.ttf' },
    },
  };
});

vi.mock('../../Image', () => ({ getBase64ImageFromURL: async () => '' }));

describe('PDF table layout', () => {
  const cjkCases = ['\u65e5\u672c\u8a9e', '\ud55c\uad6d\uc5b4'].flatMap((text) => [8, 12].flatMap((columnCount) => (
    ['HTML', 'Markdown', 'Fintel'].map((exportType) => ({ text, columnCount, exportType }))
  )));

  it.each(cjkCases)('renders $text in $columnCount columns within $exportType page bounds using Noto fonts', async ({ text, columnCount, exportType }) => {
    const headers = Array(columnCount).fill(text);
    const values = [text.repeat(30), ...Array(columnCount - 1).fill(text)];
    const html = `<table><thead><tr>${headers.map((header) => `<th>${header}</th>`).join('')}</tr></thead><tbody><tr>${values.map((value) => `<td>${value}</td>`).join('')}</tr></tbody></table>`;
    const markdown = `| ${headers.join(' | ')} |\n| ${headers.map(() => '---').join(' | ')} |\n| ${values.join(' | ')} |`;
    const pdf = exportType === 'Fintel'
      ? await htmlToPdfReport('Report', html, 'Template', [], null, { includeCoverPage: false, includeBackPage: false })
      : htmlToPdf(exportType === 'Markdown' ? 'report.md' : 'report.html', exportType === 'Markdown' ? markdown : html);
    const document = await getDocument({ data: new Uint8Array(await pdf.getBuffer()) }).promise;
    try {
      expect(document.numPages).toBe(1);
      const page = await document.getPage(1);
      const width = exportType === 'Fintel' ? (columnCount === 12 ? 1190.55 : 841.89) : 595.28;
      const margin = exportType === 'Fintel' ? (columnCount === 12 ? 8 : 10) : 40;
      expect(page.getViewport({ scale: 1 }).width).toBeCloseTo(width, 2);
      const items = (await page.getTextContent()).items.filter((item) => 'str' in item);
      expect(items.map((item) => item.str).join('').replace(/\s/g, '')).toBe([...headers, ...values].join(''));
      items.forEach((item) => {
        expect(item.transform[4]).toBeGreaterThanOrEqual(margin - 0.01);
        expect(item.transform[4] + item.width).toBeLessThanOrEqual(width - margin + 0.01);
      });
    } finally {
      await document.loadingTask.destroy();
    }
  });

  it('reduces row height by allocating more width to descriptive content', async () => {
    const description = 'The investigation identified suspicious activity affecting several systems across the organization. '.repeat(3);
    const html = `<table><thead><tr><th>ID</th><th>Description</th><th>Status</th></tr></thead><tbody><tr><td>42</td><td>${description}</td><td>Open</td></tr></tbody></table><p>EndMarker</p>`;
    const prepared = setTableFullWidth(html);
    const equalWidthContainer = document.createElement('div');
    equalWidthContainer.innerHTML = prepared;
    equalWidthContainer.querySelector('table')!.setAttribute('data-pdfmake', JSON.stringify({
      layout: 'default', widths: ['33.333333%', '33.333333%', '33.333333%'],
    }));
    pdfMake.addVirtualFileSystem(fonts);
    pdfMake.setTableLayouts(defaultTableLayout);
    const bottomPositions: number[] = [];
    for (const content of [equalWidthContainer.innerHTML, prepared]) {
      const pdf = pdfMake.createPdf({ content: htmlToPdfmake(content), pageMargins: [40, 40, 40, 40] });
      const document = await getDocument({ data: new Uint8Array(await pdf.getBuffer()) }).promise;
      try {
        expect(document.numPages).toBe(1);
        const page = await document.getPage(1);
        const text = (await page.getTextContent()).items.filter((item) => 'str' in item);
        expect(text.map((item) => item.str).join('').replace(/\s/g, '')).toContain(description.replace(/\s/g, ''));
        bottomPositions.push(text.find((item) => item.str === 'EndMarker')!.transform[5]);
      } finally {
        await document.loadingTask.destroy();
      }
    }
    expect(bottomPositions[1]).toBeGreaterThan(bottomPositions[0] + 30);
  });

  const hash = '0123456789abcdef'.repeat(4);
  const url = `https://example.com/${hash}`;
  const imageData = readFileSync('src/static/images/logo_text_white.png');
  const cases = [
    { name: 'prose', value: 'Normal words remain readable' },
    { name: 'hash', value: hash },
    { name: 'URL', value: url },
  ];

  const exportCases = ['table helper', 'HTML', 'Markdown', 'Fintel'].flatMap((exportType) => (
    [{ exportType, spanningHeader: false }, { exportType, spanningHeader: true }]
  )).flatMap((exportCase) => [4, 7, 8, 11, 12].map((columnCount) => ({ ...exportCase, columnCount })))
    .flatMap((exportCase) => (exportCase.columnCount === 4 ? ['width only', 'height attribute', 'inline height'] : ['width only'])
      .map((imageSize) => ({ ...exportCase, imageSize })));

  it.each(exportCases)('keeps complete text within margins for $exportType exports ($columnCount columns, merged header: $spanningHeader, $imageSize)', async ({ exportType, spanningHeader, columnCount, imageSize }) => {
    pdfMake.addVirtualFileSystem(fonts);
    pdfMake.setTableLayouts(defaultTableLayout);
    const imageHeight = imageSize === 'height attribute' ? 'height="300"' : imageSize === 'inline height' ? 'style="height: 300px"' : '';
    const image = `<img src="data:image/png;base64,${imageData.toString('base64')}" width="300" ${imageHeight}>`;
    const extraHeaders = Array(columnCount - 4).fill('Extra');
    const extraCells = Array(columnCount - 4).fill('Data');
    const headers = ['Name', 'Value', 'Description', ...extraHeaders, 'Status'];
    const heading = spanningHeader ? `<tr><th colspan="${columnCount}">Merged header</th></tr>` : '';
    const rows = cases.map(({ name, value }) => [name, value === url ? `<a href="${url}">${value}</a>` : value, 'Normal words remain readable', ...extraCells, 'Last column']);
    rows.push(['Image', '', '', ...extraCells, image]);
    const html = `<table><thead>${heading}<tr>${headers.map((header) => `<th>${header}</th>`).join('')}</tr></thead><tbody>${rows.map((row) => `<tr>${row.map((cell) => `<td>${cell}</td>`).join('')}</tr>`).join('')}</tbody></table>`;
    const markdown = spanningHeader
      ? `# Table\n\n${html}`
      : `| ${headers.join(' | ')} |\n| ${Array(columnCount).fill('---').join(' | ')} |\n${rows.map((row) => `| ${row.join(' | ')} |`).join('\n')}`;
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
      const preparedTable = window.document.createElement('div');
      preparedTable.innerHTML = setTableFullWidth(html, pageWidth - 2 * margin);
      const definition = JSON.parse(preparedTable.querySelector('table')!.getAttribute('data-pdfmake')!);
      const imageColumnWidth = Number.parseFloat(definition.widths[columnCount - 1]) / 100 * (pageWidth - 2 * margin);
      const padding = columnCount >= 12 ? 1 : columnCount >= 8 ? 2 : 10;
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
          expect(transform[0]).toBeCloseTo(Math.min(225, imageColumnWidth - 2 * padding - 2), 2);
          expect(transform[4]).toBeGreaterThanOrEqual(pageWidth - margin - imageColumnWidth);
          expect(Math.abs(transform[0] / transform[3])).toBeCloseTo(imageData.readUInt32BE(16) / imageData.readUInt32BE(20), 2);
        }
      });
      expect(imageCount).toBe(1);
    } finally {
      await document.loadingTask.destroy();
    }
  });
});
