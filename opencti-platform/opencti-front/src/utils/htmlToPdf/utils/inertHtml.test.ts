import { afterEach, describe, expect, it, vi } from 'vitest';
import { parseInertHtml } from './inertHtml';
import setTableFullWidth, { getMaxTableColumnCount } from './pdfTableWidth';
import addPageBreaks from './pdfPageBreaks';

// Report content is user-written HTML: an event handler such as <img onerror> runs as soon as the markup
// is parsed into an element of the live page. It must only ever be parsed into an inert document.
const HOSTILE_CONTENT = '<img src="x" onerror="window.xss = true"><table><tr><td>a</td><td>b</td></tr></table>';

const innerHtmlSetter = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML')!.set!;

// Records every element of the live page whose innerHTML is assigned
const spyOnLivePageParsing = () => {
  const liveTargets: Element[] = [];
  vi.spyOn(Element.prototype, 'innerHTML', 'set').mockImplementation(function setInnerHtml(this: Element, value: string) {
    if (this.ownerDocument === document) liveTargets.push(this);
    innerHtmlSetter.call(this, value);
  });
  return liveTargets;
};

afterEach(() => {
  vi.restoreAllMocks();
});

describe('parseInertHtml', () => {
  it('parses the content into a document separate from the live page', () => {
    const root = parseInertHtml('<p>hello</p>');
    expect(root.ownerDocument).not.toBe(document);
    expect(root.innerHTML).toBe('<p>hello</p>');
  });

  it('removes event handlers and scripts, keeping the markup the PDF export relies on', () => {
    const root = parseInertHtml(
      '<script>window.xss = true</script><img src="x" onerror="window.xss = true">'
      + '<table data-pdfmake="{}" style="width: 100%"><tr><td class="page-break">a</td></tr></table>',
    );
    expect(root.querySelector('script')).toBeNull();
    expect(root.querySelector('img')?.hasAttribute('onerror')).toBe(false);
    expect(root.querySelector('img')?.getAttribute('src')).toBe('x');
    expect(root.querySelector('table')?.getAttribute('data-pdfmake')).toBe('{}');
    expect(root.querySelector('table')?.getAttribute('style')).toBe('width: 100%');
    expect(root.querySelector('td')?.className).toBe('page-break');
  });
});

describe('PDF export HTML processing', () => {
  it('never parses report content into the live page when sizing tables', () => {
    const liveTargets = spyOnLivePageParsing();
    setTableFullWidth(HOSTILE_CONTENT);
    expect(liveTargets).toEqual([]);
  });

  it('never parses report content into the live page when counting table columns', () => {
    const liveTargets = spyOnLivePageParsing();
    expect(getMaxTableColumnCount(HOSTILE_CONTENT)).toBe(2);
    expect(liveTargets).toEqual([]);
  });

  it('never parses report content into the live page when adding page breaks', () => {
    const liveTargets = spyOnLivePageParsing();
    const result = addPageBreaks('<div class="page-break"></div><p>next</p>');
    expect(result).toBe('<div class="page-break"></div><p class="pdf-pagebreak-before">next</p>');
    expect(liveTargets).toEqual([]);
  });
});
