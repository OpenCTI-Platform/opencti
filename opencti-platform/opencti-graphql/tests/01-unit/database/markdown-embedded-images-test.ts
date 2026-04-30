import { describe, expect, it } from 'vitest';
import {
  buildEmbeddedStorageGetUri,
  collectDataUriImagesFromMarkdown,
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

  it('should detect draft-prefixed embedded storage links', () => {
    const markdown = [
      '![draft-view](/storage/view/draft%2F750a958d-816f-4b3e-b6ed-3fa8c9f42c7b%2Fembedded%2FReport%2F31342e9b-520d-43ea-a015-75c16c05cbc7%2Fcoucou%20(2)-a90ce37e.png)',
      '![draft-get](/storage/get/draft/750a958d-816f-4b3e-b6ed-3fa8c9f42c7b/embedded/Report/31342e9b-520d-43ea-a015-75c16c05cbc7b/coucou.png)',
    ].join('\n');

    const refs = extractMarkdownImageReferences(markdown);

    expect(refs).toHaveLength(2);
    expect(refs[0].isEmbeddedStorage).toBe(true);
    expect(refs[0].embeddedStoragePath).toBe('draft/750a958d-816f-4b3e-b6ed-3fa8c9f42c7b/embedded/Report/31342e9b-520d-43ea-a015-75c16c05cbc7/coucou (2)-a90ce37e.png');
    expect(refs[1].isEmbeddedStorage).toBe(true);
    expect(refs[1].embeddedStoragePath).toBe('draft/750a958d-816f-4b3e-b6ed-3fa8c9f42c7b/embedded/Report/31342e9b-520d-43ea-a015-75c16c05cbc7b/coucou.png');
  });

  it('should detect local embedded markdown links', () => {
    const markdown = '![local](embedded/upload_image_example.png)';

    const refs = extractMarkdownImageReferences(markdown);

    expect(refs).toHaveLength(1);
    expect(refs[0].isEmbeddedStorage).toBe(true);
    expect(refs[0].embeddedStoragePath).toBe('embedded/upload_image_example.png');
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

  it('should resolve local embedded links with entity context for removed-path detection', () => {
    const previousPayload = {
      description: [
        '![keep](embedded/keep.png)',
        '![remove](embedded/remove.png)',
      ].join('\n'),
    };
    const nextPayload = {
      description: '![keep](embedded/keep.png)',
    };

    const removed = findRemovedEmbeddedStoragePathsFromMarkdownFields(previousPayload, nextPayload, {
      entityType: 'Report',
      entityId: 'r-1',
    });

    expect(removed).toEqual(['embedded/Report/r-1/remove.png']);
  });
});
