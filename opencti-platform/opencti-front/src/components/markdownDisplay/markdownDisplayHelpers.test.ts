import { describe, expect, it } from 'vitest';
import { normalizeMarkdownImageUrl, resolveAndNormalizeMarkdownImageUrl } from './markdownDisplayHelpers';

describe('markdownDisplay helpers', () => {
  describe('normalizeMarkdownImageUrl', () => {
    it('keeps local embedded links contextual relative paths', () => {
      expect(normalizeMarkdownImageUrl('embedded/Report/r-1/a.png', '/')).toBe('embedded/Report/r-1/a.png');
      expect(normalizeMarkdownImageUrl('/embedded/Report/r-1/a.png', '/')).toBe('embedded/Report/r-1/a.png');
    });

    it('rewrites embedded storage/get URLs to storage/view for inline rendering', () => {
      expect(normalizeMarkdownImageUrl('/storage/get/embedded/Report/r-1/a.png', '/')).toBe('/storage/view/embedded/Report/r-1/a.png');
    });

    it('prefixes base path for /storage URLs when missing', () => {
      expect(normalizeMarkdownImageUrl('/storage/view/embedded/Report/r-1/a.png', '/opencti')).toBe('/opencti/storage/view/embedded/Report/r-1/a.png');
    });

    it('does not double-prefix base path', () => {
      expect(normalizeMarkdownImageUrl('/opencti/storage/view/embedded/Report/r-1/a.png', '/opencti')).toBe('/opencti/storage/view/embedded/Report/r-1/a.png');
    });
  });

  describe('resolveAndNormalizeMarkdownImageUrl', () => {
    it('uses resolver when provided and normalizes output', () => {
      const resolver = () => '/storage/get/embedded/Report/r-1/b.png';
      expect(resolveAndNormalizeMarkdownImageUrl('/ignored', resolver, '/opencti')).toBe('/opencti/storage/view/embedded/Report/r-1/b.png');
    });

    it('returns null when resolver returns null', () => {
      const resolver = () => null;
      expect(resolveAndNormalizeMarkdownImageUrl('/storage/view/embedded/Report/r-1/a.png', resolver, '/opencti')).toBeNull();
    });
  });
});
