import { describe, expect, it } from 'vitest';
import htmlToPdfmake from 'html-to-pdfmake';
import normalizeLineHeights from './pdfLineHeight';

const lineHeightOf = (html: string) => {
  const container = document.createElement('div');
  container.innerHTML = normalizeLineHeights(html);
  return (container.firstElementChild as HTMLElement).style.lineHeight;
};

const pdfmakeLineHeightOf = (html: string) => {
  const [paragraph] = htmlToPdfmake(normalizeLineHeights(html)) as unknown as { lineHeight?: number }[];
  return paragraph.lineHeight;
};

describe('Utils: normalizeLineHeights', () => {
  it.each([
    ['12px', '0.75'],
    ['18px', '1.13'],
    ['12pt', '1'],
    ['18pt', '1.5'],
    ['1.5em', '1.5'],
    ['2rem', '2'],
    ['0.5in', '3'],
  ])('turns line-height %s into the unitless ratio %s of the default 12pt font', (value, expected) => {
    expect(lineHeightOf(`<p style="line-height:${value}">Text</p>`)).toBe(expected);
  });

  it('computes the ratio against the element own font size', () => {
    expect(lineHeightOf('<p style="font-size:16px;line-height:24px">Text</p>')).toBe('1.5');
    expect(lineHeightOf('<p style="font-size:2em;line-height:36pt">Text</p>')).toBe('1.5');
  });

  it.each(['1.4', '150%', 'normal'])('keeps line-height %s as it is', (value) => {
    expect(lineHeightOf(`<p style="line-height:${value}">Text</p>`)).toBe(value);
  });

  it('leaves content without line-height untouched', () => {
    const html = '<p style="color: red;">Text</p><table><tr><td>A</td></tr></table>';
    expect(normalizeLineHeights(html)).toBe(html);
  });

  it('gives pdfmake a line height close to the HTML rendering instead of a point value (#19198)', () => {
    const html = '<p style="line-height:12px">A paragraph long enough to wrap on several lines of an A4 page.</p>';
    const [raw] = htmlToPdfmake(html) as unknown as { lineHeight?: number }[];
    expect(raw.lineHeight).toBe(9);
    expect(pdfmakeLineHeightOf(html)).toBe(0.75);
    expect(pdfmakeLineHeightOf('<p style="line-height:24px">Text</p>')).toBe(1.5);
  });

  it('keeps quotes of the other kind inside the style attribute', () => {
    expect(lineHeightOf('<p style="font-family: \'Arial\'; line-height:24px">Text</p>')).toBe('1.5');
    expect(lineHeightOf('<p style=\'font-family: "Arial"; line-height:24px\'>Text</p>')).toBe('1.5');
  });

  it('does not touch line-height written outside a style attribute', () => {
    const html = '<p data-note="line-height:12px">line-height:12px</p>';
    expect(normalizeLineHeights(html)).toBe(html);
  });

  it('normalizes nested elements independently', () => {
    const container = document.createElement('div');
    container.innerHTML = normalizeLineHeights('<div style="line-height:24pt"><span style="font-size:24pt;line-height:24pt">Text</span></div>');
    expect((container.querySelector('div') as HTMLElement).style.lineHeight).toBe('2');
    expect((container.querySelector('span') as HTMLElement).style.lineHeight).toBe('1');
  });
});
