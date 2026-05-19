import { describe, expect, it } from 'vitest';
import { extractEmbeddedStoragePathsFromMarkdown, getImageFiles, getMarkdownImageDragFeedback, isSvgImageFile } from './markdownImageFieldHelpers';

describe('markdown image field helpers', () => {
  it('extracts embedded storage paths from local embedded links', () => {
    const markdown = [
      '![rel](embedded/Report/r-1/image-a.png)',
      '![root](/embedded/Report/r-1/image-b.png)',
      '![ext](https://example.org/image.png)',
    ].join('\n');

    expect(extractEmbeddedStoragePathsFromMarkdown(markdown).sort()).toEqual([
      'embedded/Report/r-1/image-a.png',
      'embedded/Report/r-1/image-b.png',
    ]);
  });

  it('ignores storage/get and storage/view URLs', () => {
    const markdown = [
      '![b](/storage/view/embedded/Report/r-1/image-b.png)',
      '![ignored](/storage/get/embedded/Report/r-1/image-a.png)',
      '![c](https://example.org/image.png)',
    ].join('\n');

    expect(extractEmbeddedStoragePathsFromMarkdown(markdown)).toEqual([]);
  });

  it('deduplicates repeated references to the same embedded path', () => {
    const markdown = [
      '![first](embedded/Report/r-1/dup.png)',
      '![second](embedded/Report/r-1/dup.png)',
    ].join('\n');

    expect(extractEmbeddedStoragePathsFromMarkdown(markdown)).toEqual([
      'embedded/Report/r-1/dup.png',
    ]);
  });

  it('ignores non-embedded URLs and malformed markdown image syntax', () => {
    const markdown = [
      '![ok](https://images.pexels.com/photos/1/pexels-photo.jpeg)',
      '![broken](/storage/get/embedded/Report/r-1/missing-closing.png',
      '![also-broken]/storage/get/embedded/Report/r-1/ignored.png)',
    ].join('\n');

    expect(extractEmbeddedStoragePathsFromMarkdown(markdown)).toEqual([]);
  });

  it('rejects suspicious paths containing traversal segments', () => {
    const markdown = '![bad](embedded/Report/r-1/../secrets.png)';

    expect(extractEmbeddedStoragePathsFromMarkdown(markdown)).toEqual([]);
  });

  it('supports angle-bracket destinations and optional title text', () => {
    const markdown = [
      '![angled](<embedded/Report/r-1/from-angle.png>)',
      '![titled](embedded/Report/r-1/with-title.png "My image")',
    ].join('\n');

    expect(extractEmbeddedStoragePathsFromMarkdown(markdown).sort()).toEqual([
      'embedded/Report/r-1/from-angle.png',
      'embedded/Report/r-1/with-title.png',
    ]);
  });

  it('filters out svg files from markdown upload candidates', () => {
    const png = new File(['png'], 'sample.png', { type: 'image/png' });
    const svg = new File(['svg'], 'sample.svg', { type: 'image/svg+xml' });
    const jpeg = new File(['jpeg'], 'sample.jpg', { type: 'image/jpeg' });

    expect(getImageFiles([png, svg, jpeg]).map((f) => f.name)).toEqual(['sample.png', 'sample.jpg']);
  });

  it('detects svg by mime type and extension', () => {
    const svgMime = new File(['svg'], 'vector.bin', { type: 'image/svg+xml' });
    const svgExt = new File(['svg'], 'vector.SVG', { type: '' });
    const png = new File(['png'], 'sample.png', { type: 'image/png' });

    expect(isSvgImageFile(svgMime)).toBe(true);
    expect(isSvgImageFile(svgExt)).toBe(true);
    expect(isSvgImageFile(png)).toBe(false);
  });

  it('marks dragged svg payloads as invalid for real-time feedback', () => {
    const feedback = getMarkdownImageDragFeedback({
      types: ['Files'],
      items: [{ kind: 'file', type: 'image/svg+xml' }],
    } as unknown as DataTransfer);

    expect(feedback).toBe('invalid');
  });

  it('marks dragged raster image payloads as valid for real-time feedback', () => {
    const feedback = getMarkdownImageDragFeedback({
      types: ['Files'],
      items: [{ kind: 'file', type: 'image/png' }],
    } as unknown as DataTransfer);

    expect(feedback).toBe('valid');
  });
});
