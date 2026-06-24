import { describe, expect, it } from 'vitest';
import { extractMarkdownPreviewImages, isAllowedUploadedImageUrl } from './markdownPreviewImageUtils';

describe('markdown preview image utils', () => {
  describe('isAllowedUploadedImageUrl', () => {
    it('rejects platform relative storage URLs', () => {
      expect(isAllowedUploadedImageUrl('/storage/view/embedded/Report/r-1/image.png')).toBe(false);
      expect(isAllowedUploadedImageUrl('/storage/get/embedded/Report/r-1/image.png')).toBe(false);
      expect(isAllowedUploadedImageUrl('/public/storage/view/image.png')).toBe(false);
    });

    it('accepts canonical local embedded links', () => {
      expect(isAllowedUploadedImageUrl('embedded/Report/r-1/image.png')).toBe(true);
      expect(isAllowedUploadedImageUrl('/embedded/Report/r-1/image.png')).toBe(true);
    });

    it('accepts temp image scheme and http/https URLs, rejects dangerous URLs', () => {
      expect(isAllowedUploadedImageUrl('opencti-image://temp/abc123')).toBe(true);
      expect(isAllowedUploadedImageUrl('https://example.org/image.png')).toBe(true);
      expect(isAllowedUploadedImageUrl('http://example.org/image.png')).toBe(true);
      expect(isAllowedUploadedImageUrl('javascript:alert(1)')).toBe(false);
      expect(isAllowedUploadedImageUrl('javascript:alert(1)//storage/view/embedded/Report/r-1/image.png')).toBe(false);
      expect(isAllowedUploadedImageUrl('data:image/png;base64,abcd')).toBe(false);
      expect(isAllowedUploadedImageUrl('storage/view/embedded/Report/r-1/image.png')).toBe(false);
    });
  });

  describe('extractMarkdownPreviewImages', () => {
    it('extracts canonical local embedded images after resolution', () => {
      const markdown = '![local](embedded/Report/r-1/local.png)';
      const resolveImageUrl = (url: string) => `/storage/view/${url}`;

      expect(extractMarkdownPreviewImages(markdown, resolveImageUrl)).toEqual([
        {
          src: '/storage/view/embedded/Report/r-1/local.png',
          alt: 'local',
        },
      ]);
    });

    it('extracts and resolves markdown images with alt text', () => {
      const markdown = [
        '![first](embedded/Report/r-1/one.png)',
        '![second](https://example.org/two.png)',
      ].join('\n');

      const resolveImageUrl = (url: string) => `/resolved?u=${encodeURIComponent(url)}`;
      expect(extractMarkdownPreviewImages(markdown, resolveImageUrl)).toEqual([
        {
          src: '/resolved?u=embedded%2FReport%2Fr-1%2Fone.png',
          alt: 'first',
        },
        {
          src: '/resolved?u=https%3A%2F%2Fexample.org%2Ftwo.png',
          alt: 'second',
        },
      ]);
    });

    it('deduplicates by resolved src and alt text', () => {
      const markdown = [
        '![same](embedded/Report/r-1/dup.png)',
        '![same](embedded/Report/r-1/dup.png)',
        '![different-alt](embedded/Report/r-1/dup.png)',
      ].join('\n');

      const resolveImageUrl = () => '/resolved/dup.png';
      expect(extractMarkdownPreviewImages(markdown, resolveImageUrl)).toEqual([
        { src: '/resolved/dup.png', alt: 'same' },
        { src: '/resolved/dup.png', alt: 'different-alt' },
      ]);
    });

    it('supports nested parentheses and skips non-resolvable URLs', () => {
      const markdown = [
        '![chart](embedded/Report/r-1/figure(1).png)',
        '![ignored](https://example.org/skip.png)',
      ].join('\n');

      const resolveImageUrl = (url: string) => {
        if (url.includes('skip.png')) {
          return null;
        }
        return url;
      };

      expect(extractMarkdownPreviewImages(markdown, resolveImageUrl)).toEqual([
        { src: 'embedded/Report/r-1/figure(1).png', alt: 'chart' },
      ]);
    });
  });
});
