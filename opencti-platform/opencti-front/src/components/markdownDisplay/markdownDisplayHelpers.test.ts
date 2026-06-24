import { describe, expect, it } from 'vitest';
import { normalizeEmbeddedImageDestinations, normalizeMarkdownImageUrl, resolveAndNormalizeMarkdownImageUrl } from './markdownDisplayHelpers';

describe('markdownDisplay helpers', () => {
  describe('normalizeMarkdownImageUrl', () => {
    it('keeps local embedded links contextual relative paths', () => {
      expect(normalizeMarkdownImageUrl('embedded/Report/r-1/a.png', '/')).toBe('embedded/Report/r-1/a.png');
      expect(normalizeMarkdownImageUrl('/embedded/Report/r-1/a.png', '/')).toBe('embedded/Report/r-1/a.png');
    });

    it('does not rewrite storage/get URLs anymore', () => {
      expect(normalizeMarkdownImageUrl('/storage/get/embedded/Report/r-1/a.png', '/')).toBe('/storage/get/embedded/Report/r-1/a.png');
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
      expect(resolveAndNormalizeMarkdownImageUrl('/ignored', resolver, '/opencti', '/dashboard/analyses/reports/r-1')).toBe('/opencti/storage/get/embedded/Report/r-1/b.png');
    });

    it('returns null when resolver returns null', () => {
      const resolver = () => null;
      expect(resolveAndNormalizeMarkdownImageUrl('/storage/view/embedded/Report/r-1/a.png', resolver, '/opencti', '/dashboard/analyses/reports/r-1')).toBeNull();
    });

    it('resolves embedded relative links against current page path when no resolver is provided', () => {
      expect(resolveAndNormalizeMarkdownImageUrl('embedded/image.png', undefined, '/', '/dashboard/analyses/reports/fcd6fa59-c0bb-4e25-8a9b-b54f4917ddef')).toBe('/dashboard/analyses/reports/fcd6fa59-c0bb-4e25-8a9b-b54f4917ddef/embedded/image.png');
    });

    it('keeps non-embedded links unchanged when no resolver is provided', () => {
      expect(resolveAndNormalizeMarkdownImageUrl('https://example.org/image.png', undefined, '/', '/dashboard/analyses/reports/fcd6fa59-c0bb-4e25-8a9b-b54f4917ddef')).toBe('https://example.org/image.png');
    });
  });

  describe('normalizeEmbeddedImageDestinations', () => {
    it('wraps embedded destinations containing spaces and preserves title', () => {
      const markdown = '![img](embedded/my file.png "Title")';
      expect(normalizeEmbeddedImageDestinations(markdown)).toBe('![img](<embedded/my%20file.png> "Title")');
    });

    it('keeps non-embedded destinations unchanged', () => {
      const markdown = '![img](https://example.org/my file.png)';
      expect(normalizeEmbeddedImageDestinations(markdown)).toBe(markdown);
    });
  });
});
