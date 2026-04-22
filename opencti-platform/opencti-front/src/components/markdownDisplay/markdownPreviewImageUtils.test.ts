import { describe, expect, it } from 'vitest';
import { extractMarkdownPreviewImages, isAllowedUploadedImageUrl } from './markdownPreviewImageUtils';

describe('markdown preview image utils', () => {
  describe('isAllowedUploadedImageUrl', () => {
    it('accepts platform storage URLs', () => {
      expect(isAllowedUploadedImageUrl('/storage/view/embedded/Report/r-1/image.png')).toBe(true);
      expect(isAllowedUploadedImageUrl('/storage/get/embedded/Report/r-1/image.png')).toBe(true);
    });

    it('accepts temp image scheme and normal web URLs, rejects dangerous URLs', () => {
      expect(isAllowedUploadedImageUrl('opencti-image://temp/abc123')).toBe(true);
      expect(isAllowedUploadedImageUrl('https://example.org/image.png')).toBe(true);
      expect(isAllowedUploadedImageUrl('javascript:alert(1)')).toBe(false);
    });
  });

  describe('extractMarkdownPreviewImages', () => {
    it('extracts and resolves markdown images with alt text', () => {
      const markdown = [
        '![first](/storage/view/embedded/Report/r-1/one.png)',
        '![second](https://example.org/two.png)',
      ].join('\n');

      const resolveImageUrl = (url: string) => `/resolved?u=${encodeURIComponent(url)}`;
      expect(extractMarkdownPreviewImages(markdown, resolveImageUrl)).toEqual([
        {
          src: '/resolved?u=%2Fstorage%2Fview%2Fembedded%2FReport%2Fr-1%2Fone.png',
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
        '![same](/storage/view/embedded/Report/r-1/dup.png)',
        '![same](/storage/get/embedded/Report/r-1/dup.png)',
        '![different-alt](/storage/get/embedded/Report/r-1/dup.png)',
      ].join('\n');

      const resolveImageUrl = () => '/resolved/dup.png';
      expect(extractMarkdownPreviewImages(markdown, resolveImageUrl)).toEqual([
        { src: '/resolved/dup.png', alt: 'same' },
        { src: '/resolved/dup.png', alt: 'different-alt' },
      ]);
    });

    it('supports nested parentheses and skips non-resolvable URLs', () => {
      const markdown = [
        '![chart](/storage/view/embedded/Report/r-1/figure(1).png)',
        '![ignored](https://example.org/skip.png)',
      ].join('\n');

      const resolveImageUrl = (url: string) => {
        if (url.includes('skip.png')) {
          return null;
        }
        return url;
      };

      expect(extractMarkdownPreviewImages(markdown, resolveImageUrl)).toEqual([
        { src: '/storage/view/embedded/Report/r-1/figure(1).png', alt: 'chart' },
      ]);
    });
  });
});
