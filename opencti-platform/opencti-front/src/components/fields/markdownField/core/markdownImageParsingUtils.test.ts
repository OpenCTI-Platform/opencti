import { describe, expect, it } from 'vitest';
import { extractMarkdownImageReferences, parseMarkdownImageDestination } from './markdownImageParsingUtils';

describe('markdown image parsing utils', () => {
  describe('parseMarkdownImageDestination', () => {
    it('parses plain destinations', () => {
      expect(parseMarkdownImageDestination('/storage/view/embedded/a.png')).toBe('/storage/view/embedded/a.png');
    });

    it('parses angle-bracket destinations', () => {
      expect(parseMarkdownImageDestination('</storage/get/embedded/a.png>')).toBe('/storage/get/embedded/a.png');
    });

    it('ignores title text after URL', () => {
      expect(parseMarkdownImageDestination('/storage/view/embedded/a.png "Title"')).toBe('/storage/view/embedded/a.png');
    });

    it('returns null for invalid destination', () => {
      expect(parseMarkdownImageDestination('')).toBeNull();
      expect(parseMarkdownImageDestination('   ')).toBeNull();
      expect(parseMarkdownImageDestination('<not-closed')).toBeNull();
    });
  });

  describe('extractMarkdownImageReferences', () => {
    it('extracts alt text and URL for valid markdown images', () => {
      const markdown = [
        '![alpha](/storage/view/embedded/Report/r-1/a.png)',
        '![beta](</storage/get/embedded/Report/r-1/b.png>)',
      ].join('\n');

      expect(extractMarkdownImageReferences(markdown)).toEqual([
        { altText: 'alpha', imageUrl: '/storage/view/embedded/Report/r-1/a.png' },
        { altText: 'beta', imageUrl: '/storage/get/embedded/Report/r-1/b.png' },
      ]);
    });

    it('supports nested parentheses in URL', () => {
      const markdown = '![chart](/storage/view/embedded/Report/r-1/figure(1).png)';

      expect(extractMarkdownImageReferences(markdown)).toEqual([
        { altText: 'chart', imageUrl: '/storage/view/embedded/Report/r-1/figure(1).png' },
      ]);
    });

    it('skips malformed markdown image syntax when stopping at top-level line breaks', () => {
      const markdown = [
        '![ok](/storage/view/embedded/Report/r-1/a.png)',
        '![broken](/storage/view/embedded/Report/r-1/missing-closing.png',
        '![also-broken]/storage/view/embedded/Report/r-1/no-paren.png)',
      ].join('\n');

      expect(extractMarkdownImageReferences(markdown, { stopAtLineBreakAtTopLevel: true })).toEqual([
        { altText: 'ok', imageUrl: '/storage/view/embedded/Report/r-1/a.png' },
      ]);
    });

    it('stops at top-level line breaks when requested', () => {
      const multiline = '![bad](/storage/view/embedded/Report/r-1/a.png\n"Title")';

      expect(extractMarkdownImageReferences(multiline, { stopAtLineBreakAtTopLevel: true })).toEqual([]);
      expect(extractMarkdownImageReferences(multiline, { stopAtLineBreakAtTopLevel: false })).toEqual([
        { altText: 'bad', imageUrl: '/storage/view/embedded/Report/r-1/a.png' },
      ]);
    });
  });
});
