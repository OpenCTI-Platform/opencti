import { describe, expect, it } from 'vitest';
import {
  buildEmbeddedStorageGetUri,
  collectDataUriImagesFromMarkdown,
  collectEmbeddedStoragePathsFromMarkdownFields,
  extractMarkdownImageReferences,
  findRemovedEmbeddedStoragePathsFromMarkdownFields,
  parseDataUriImage,
  rewriteMarkdownImageUrls,
} from '../../../src/database/markdown-embedded-images';

describe('markdown-embedded-images utility', () => {
  it('should detect embedded markdown image links and extract their storage path', () => {
    const markdown = [
      'before',
      '![inline](/storage/get/embedded/Report/abc123/file.png)',
      '![other](https://example.org/storage/get/embedded/Note/n-1/img.webp)',
      '![ignore](/storage/get/import/global/report.pdf)',
    ].join('\n');

    const refs = extractMarkdownImageReferences(markdown);

    expect(refs).toHaveLength(3);
    expect(refs[0].isEmbeddedStorage).toBe(true);
    expect(refs[0].embeddedStoragePath).toBe('embedded/Report/abc123/file.png');
    expect(refs[1].isEmbeddedStorage).toBe(true);
    expect(refs[1].embeddedStoragePath).toBe('embedded/Note/n-1/img.webp');
    expect(refs[2].isEmbeddedStorage).toBe(false);
  });

  it('should rewrite only embedded storage image links', () => {
    const markdown = [
      '![one](/storage/get/embedded/Report/1/a.png)',
      '![two](https://example.org/no-change.png)',
    ].join('\n');

    const { markdown: rewritten, replacedCount } = rewriteMarkdownImageUrls(markdown, (ref) => {
      if (!ref.isEmbeddedStorage) {
        return undefined;
      }
      return 'data:image/png;base64,Zm9v';
    });

    expect(replacedCount).toBe(1);
    expect(rewritten).toContain('![one](data:image/png;base64,Zm9v)');
    expect(rewritten).toContain('![two](https://example.org/no-change.png)');
  });

  it('should parse and validate a valid image data URI', () => {
    const dataUri = `data:image/png;base64,${Buffer.from('png-bytes').toString('base64')}`;

    const parsed = parseDataUriImage(dataUri);

    expect(parsed.mimeType).toBe('image/png');
    expect(parsed.byteLength).toBe(Buffer.byteLength('png-bytes'));
    expect(parsed.dedupeKey).toHaveLength(64);
  });

  it('should reject invalid data URI image format', () => {
    expect(() => parseDataUriImage('not-a-data-uri')).toThrowError('Invalid data URI image format');
  });

  it('should reject unsupported mime type', () => {
    const dataUri = `data:image/bmp;base64,${Buffer.from('bmp').toString('base64')}`;

    expect(() => parseDataUriImage(dataUri)).toThrowError('Unsupported data URI image mime type: image/bmp');
  });

  it('should reject svg mime type explicitly', () => {
    const dataUri = `data:image/svg+xml;base64,${Buffer.from('<svg/>').toString('base64')}`;

    expect(() => parseDataUriImage(dataUri)).toThrowError('Unsupported data URI image mime type: image/svg+xml');
  });

  it('should reject non-base64 image payload', () => {
    expect(() => parseDataUriImage('data:image/png,abcd')).toThrowError('Data URI image payload must be base64 encoded');
  });

  it('should enforce max per-image size', () => {
    const payload = Buffer.from('too-big').toString('base64');
    const dataUri = `data:image/png;base64,${payload}`;

    expect(() => parseDataUriImage(dataUri, { maxImageSizeBytes: 4 })).toThrowError('Data URI image exceeds max size (4 bytes)');
  });

  it('should dedupe duplicate data URI images in one markdown description', () => {
    const payload = Buffer.from('same-bytes').toString('base64');
    const dataUri = `data:image/png;base64,${payload}`;

    const markdown = [
      `![a](${dataUri})`,
      `![b](${dataUri})`,
    ].join('\n');

    const collected = collectDataUriImagesFromMarkdown(markdown);

    expect(collected.totalImagesDetected).toBe(2);
    expect(collected.images).toHaveLength(1);
    expect(collected.images[0].occurrences).toHaveLength(2);
  });

  it('should enforce max total markdown payload budget', () => {
    const one = `data:image/png;base64,${Buffer.from('12345').toString('base64')}`;
    const two = `data:image/png;base64,${Buffer.from('67890').toString('base64')}`;
    const markdown = `![a](${one})\n![b](${two})`;

    expect(() => collectDataUriImagesFromMarkdown(markdown, { maxTotalSizeBytes: 8 }))
      .toThrowError('Data URI images exceed max total size (8 bytes)');
  });

  it('should generate an embedded storage URI replacement', () => {
    const uri = buildEmbeddedStorageGetUri('Report', 'report--123', 'abc.png');
    expect(uri).toBe('/storage/get/embedded/Report/report--123/abc.png');
  });

  it('should compute removed embedded storage paths from markdown field updates', () => {
    const previousPayload = {
      description: [
        '![keep](/storage/get/embedded/Report/r-1/keep.png)',
        '![remove](/storage/get/embedded/Report/r-1/remove.png)',
      ].join('\n'),
      content: '![other](/storage/get/embedded/Report/r-2/nope.png)',
    };
    const nextPayload = {
      description: '![keep](/storage/get/embedded/Report/r-1/keep.png)',
      content: 'No markdown image anymore',
    };

    const removed = findRemovedEmbeddedStoragePathsFromMarkdownFields(previousPayload, nextPayload, {
      entityType: 'Report',
      entityId: 'r-1',
    });

    expect(removed).toEqual(['embedded/Report/r-1/remove.png']);
  });
});
