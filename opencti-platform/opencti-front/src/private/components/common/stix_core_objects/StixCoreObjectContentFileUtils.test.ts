import { describe, expect, it } from 'vitest';
import {
  filterContentTabFiles,
  getContentTabImagePreviewPath,
  isContentTabImage,
  isPreviewOnlyFile,
  resolveContentFileMimeType,
} from './StixCoreObjectContentFileUtils';

const file = (id: string, mimetype: string | null, lastModified: string) => ({ id, lastModified, metaData: { mimetype } });

describe('filterContentTabFiles', () => {
  it('keeps PNG and JPEG images together with the other supported files, sorted by last modified', () => {
    const files = [
      file('report.pdf', 'application/pdf', '2026-01-04T00:00:00Z'),
      file('shot.png', 'image/png', '2026-01-02T00:00:00Z'),
      file('notes.md', 'text/markdown', '2026-01-03T00:00:00Z'),
      file('photo.jpg', 'image/jpeg', '2026-01-01T00:00:00Z'),
    ];
    expect(filterContentTabFiles(files).map((f) => f.id)).toEqual(['photo.jpg', 'shot.png', 'notes.md', 'report.pdf']);
  });

  it('keeps hiding file types the Content tab does not support', () => {
    const files = [
      file('anim.gif', 'image/gif', '2026-01-01T00:00:00Z'),
      file('logo.svg', 'image/svg+xml', '2026-01-01T00:00:00Z'),
      file('archive.zip', 'application/zip', '2026-01-01T00:00:00Z'),
      file('unknown', null, '2026-01-01T00:00:00Z'),
    ];
    expect(filterContentTabFiles(files)).toEqual([]);
  });
});

describe('isContentTabImage', () => {
  it('recognises PNG and JPEG only', () => {
    expect(isContentTabImage('image/png')).toBe(true);
    expect(isContentTabImage('image/jpeg')).toBe(true);
    expect(isContentTabImage('image/gif')).toBe(false);
    expect(isContentTabImage('application/pdf')).toBe(false);
    expect(isContentTabImage(undefined)).toBe(false);
  });
});

describe('isPreviewOnlyFile', () => {
  it('is true for PDF and images, whose content must not be fetched as text', () => {
    expect(isPreviewOnlyFile('application/pdf')).toBe(true);
    expect(isPreviewOnlyFile('image/png')).toBe(true);
    expect(isPreviewOnlyFile('image/jpeg')).toBe(true);
  });

  it('is false for editable text files', () => {
    expect(isPreviewOnlyFile('text/plain')).toBe(false);
    expect(isPreviewOnlyFile('text/html')).toBe(false);
    expect(isPreviewOnlyFile('text/markdown')).toBe(false);
  });
});

describe('resolveContentFileMimeType', () => {
  it('uses the known mime type when the file is already listed', () => {
    expect(resolveContentFileMimeType('import/Report/abc/shot', 'image/png')).toBe('image/png');
  });

  it('guesses images and PDF from the extension of a file not listed yet (just uploaded)', () => {
    expect(resolveContentFileMimeType('import/Report/abc/shot.PNG', undefined)).toBe('image/png');
    expect(resolveContentFileMimeType('import/Report/abc/photo.jpg', undefined)).toBe('image/jpeg');
    expect(resolveContentFileMimeType('import/Report/abc/photo.jpeg', null)).toBe('image/jpeg');
    expect(resolveContentFileMimeType('import/Report/abc/doc.pdf', undefined)).toBe('application/pdf');
  });

  it('returns undefined when the type cannot be told', () => {
    expect(resolveContentFileMimeType('import/Report/abc/notes.txt', undefined)).toBeUndefined();
  });
});

describe('getContentTabImagePreviewPath', () => {
  const fileId = 'import/Report/abc/my shot.png';

  it('points the Data tab to the image preview in the Content tab', () => {
    expect(getContentTabImagePreviewPath('/dashboard/analyses/reports/abc/files', 'Report', fileId, 'image/png'))
      .toBe('/dashboard/analyses/reports/abc/content?forceFile=true&currentFileId=import%2FReport%2Fabc%2Fmy+shot.png');
  });

  it('is null for files that are not previewable images', () => {
    expect(getContentTabImagePreviewPath('/dashboard/analyses/reports/abc/files', 'Report', 'a.pdf', 'application/pdf')).toBeNull();
    expect(getContentTabImagePreviewPath('/dashboard/analyses/reports/abc/files', 'Report', 'a.gif', 'image/gif')).toBeNull();
  });

  it('is null for entities without a Content tab', () => {
    expect(getContentTabImagePreviewPath('/dashboard/analyses/notes/abc/files', 'Note', fileId, 'image/png')).toBeNull();
    expect(getContentTabImagePreviewPath('/dashboard/events/observed_data/abc/files', 'Observed-Data', fileId, 'image/png')).toBeNull();
  });

  it('is null for Artifact files, which may be malicious and keep their download warning', () => {
    expect(getContentTabImagePreviewPath('/dashboard/observations/artifacts/abc/files', 'Artifact', fileId, 'image/png')).toBeNull();
  });

  it('is null outside an entity Data tab', () => {
    expect(getContentTabImagePreviewPath('/dashboard/data/import', 'Report', fileId, 'image/png')).toBeNull();
  });
});
