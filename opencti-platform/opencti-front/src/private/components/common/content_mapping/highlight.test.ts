import { describe, expect, it } from 'vitest';
import { buildMatcher, clearHighlights, highlightElement, highlightToHtml, HighlightTerm, splitText } from './highlight';

const term = (key: string, text = key, status: HighlightTerm['status'] = 'mapped'): HighlightTerm => ({ key, text, status, color: '#ff9800' });

describe('splitText', () => {
  it('should match whole values only, case-insensitively, longest first', () => {
    const matcher = buildMatcher([term('frp', 'FRP'), term('fast reverse proxy (frp)', 'Fast Reverse Proxy (FRP)'), term('cia', 'CIA')]);
    const parts = splitText('The actor deployed Fast Reverse Proxy (FRP), not CIAFBI; frp again.', matcher);
    expect(parts.filter((p) => p.term).map((p) => [p.text, p.term?.key])).toEqual([
      ['Fast Reverse Proxy (FRP)', 'fast reverse proxy (frp)'],
      ['frp', 'frp'],
    ]);
  });

  it('should match defanged values as they are written', () => {
    const matcher = buildMatcher([term('update-check[.]net', 'update-check[.]net', 'new')]);
    expect(splitText('domain update-check[.]net, resolving', matcher)[1]).toEqual({ text: 'update-check[.]net', term: term('update-check[.]net', 'update-check[.]net', 'new') });
  });
});

describe('highlightElement', () => {
  it('should wrap occurrences in marks, count them, and leave links usable', () => {
    const root = document.createElement('div');
    root.innerHTML = '<p>APT41 used <a href="https://example.com/apt41">the APT41 report</a>.</p>';
    const counts = highlightElement(root, [term('apt41', 'APT41')]);
    expect(counts).toEqual({ apt41: 2 });
    expect(root.querySelector('a')?.getAttribute('href')).toBe('https://example.com/apt41');
    expect(root.querySelectorAll('mark[data-cm-key="apt41"]')).toHaveLength(2);
    expect(root.querySelector('mark')?.dataset.cmStatus).toBe('mapped');
  });

  it('should not highlight twice, and be undone', () => {
    const root = document.createElement('div');
    root.innerHTML = '<p>DeedRAT and DeedRAT</p>';
    highlightElement(root, [term('deedrat', 'DeedRAT')]);
    highlightElement(root, [term('deedrat', 'DeedRAT')]);
    expect(root.querySelectorAll('mark')).toHaveLength(2);
    clearHighlights(root);
    expect(root.innerHTML).toBe('<p>DeedRAT and DeedRAT</p>');
  });
});

describe('highlightToHtml', () => {
  it('should escape the text around the marks', () => {
    const html = highlightToHtml('<b>APT41</b>', buildMatcher([term('apt41', 'APT41', 'suggested')]));
    expect(html).toBe('&lt;b&gt;<mark data-cm-key="apt41" data-cm-status="suggested" style="--cm-color:#ff9800">APT41</mark>&lt;/b&gt;');
  });
});
