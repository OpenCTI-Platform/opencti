import { describe, expect, it } from 'vitest';
import { extractEmbeddedStoragePathsFromMarkdown } from './markdownImageFieldHelpers';

describe('markdown image field helpers', () => {
  it('extracts embedded storage paths from relative storage/get and storage/view URLs', () => {
    const markdown = [
      '![a](/storage/get/embedded/Report/r-1/image-a.png)',
      '![b](/storage/view/embedded/Report/r-1/image-b.png)',
      '![c](https://example.org/image.png)',
    ].join('\n');

    expect(extractEmbeddedStoragePathsFromMarkdown(markdown).sort()).toEqual([
      'embedded/Report/r-1/image-a.png',
      'embedded/Report/r-1/image-b.png',
    ]);
  });

  it('extracts embedded storage paths from encoded view URLs (relative and absolute)', () => {
    const markdown = [
      '![rel](/storage/view/embedded%2FReport%2Fr-1%2Fimage-c.png)',
      '![abs](https://platform.local/storage/view/embedded%2FReport%2Fr-1%2Fimage-d.png)',
    ].join('\n');

    expect(extractEmbeddedStoragePathsFromMarkdown(markdown).sort()).toEqual([
      'embedded/Report/r-1/image-c.png',
      'embedded/Report/r-1/image-d.png',
    ]);
  });

  it('handles markdown image destinations with nested parentheses in filenames', () => {
    const markdown = '![chart](/storage/view/embedded/Report/r-1/figure(1).png)';

    expect(extractEmbeddedStoragePathsFromMarkdown(markdown)).toEqual([
      'embedded/Report/r-1/figure(1).png',
    ]);
  });

  it('deduplicates repeated references to the same embedded path', () => {
    const markdown = [
      '![first](/storage/get/embedded/Report/r-1/dup.png)',
      '![second](/storage/view/embedded/Report/r-1/dup.png)',
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
    const markdown = '![bad](/storage/get/embedded/Report/r-1/../secrets.png)';

    expect(extractEmbeddedStoragePathsFromMarkdown(markdown)).toEqual([]);
  });

  it('supports angle-bracket destinations and optional title text', () => {
    const markdown = [
      '![angled](</storage/get/embedded/Report/r-1/from-angle.png>)',
      '![titled](/storage/view/embedded/Report/r-1/with-title.png "My image")',
    ].join('\n');

    expect(extractEmbeddedStoragePathsFromMarkdown(markdown).sort()).toEqual([
      'embedded/Report/r-1/from-angle.png',
      'embedded/Report/r-1/with-title.png',
    ]);
  });
});
