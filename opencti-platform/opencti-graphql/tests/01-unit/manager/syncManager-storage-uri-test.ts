import { describe, expect, it } from 'vitest';
import { buildSyncStorageFetchUri, encodeStorageRelativePath } from '../../../src/manager/syncManager';

describe('syncManager storage fetch URI encoding', () => {
  describe('encodeStorageRelativePath', () => {
    it('encodes reserved characters in a filename segment', () => {
      const input = 'storage/get/import/Case-Incident/bb58de87/#s18bfbad0ee7d0_-endpoint.csv';
      const output = encodeStorageRelativePath(input);
      expect(output).toBe('storage/get/import/Case-Incident/bb58de87/%23s18bfbad0ee7d0_-endpoint.csv');
      // slashes are preserved as path separators
      expect(output.split('/').length).toBe(input.split('/').length);
    });

    it('encodes other reserved characters (?, space, %23 already encoded stays stable)', () => {
      expect(encodeStorageRelativePath('a/b c/d?e.csv')).toBe('a/b%20c/d%3Fe.csv');
      // idempotent: already-encoded input is not double-encoded
      expect(encodeStorageRelativePath('a/%23file.csv')).toBe('a/%23file.csv');
      expect(encodeStorageRelativePath(encodeStorageRelativePath('a/#file.csv'))).toBe('a/%23file.csv');
    });

    it('keeps malformed percent-sequences untouched instead of throwing', () => {
      expect(encodeStorageRelativePath('a/100%done.csv')).toBe('a/100%25done.csv');
    });
  });

  describe('buildSyncStorageFetchUri', () => {
    const syncUri = 'https://instance-a.example.com';

    it('encodes a # in the filename of a relative storage path (regression)', () => {
      const fileUri = '/storage/get/import/Case-Incident/bb58de87-908e-4fcb-af80-339562208b8c/#s18bfbad0ee7d0_-endpoint-allow_operation.csv';
      const fetchUri = buildSyncStorageFetchUri(syncUri, fileUri);
      expect(fetchUri).toBe(
        'https://instance-a.example.com/storage/get/import/Case-Incident/bb58de87-908e-4fcb-af80-339562208b8c/%23s18bfbad0ee7d0_-endpoint-allow_operation.csv',
      );
      // the '#' must not survive raw (it would be treated as a URL fragment by the HTTP client)
      expect(fetchUri).not.toContain('/#');
    });

    it('builds a valid URL whose path (after host) no longer contains a raw fragment delimiter', () => {
      const fileUri = '/storage/get/import/Report/abc/weird#name?x.csv';
      const fetchUri = buildSyncStorageFetchUri(syncUri, fileUri) as string;
      const parsed = new URL(fetchUri);
      expect(parsed.hash).toBe('');
      expect(parsed.search).toBe('');
      expect(parsed.pathname.endsWith('weird%23name%3Fx.csv')).toBe(true);
    });

    // Markdown embedded urls are the stored file name encoded once: the fetch url must encode the same name once (#19008).
    describe('embedded markdown image urls', () => {
      const context = { entityType: 'Report', entityId: 'r-1' };
      const fetchBase = 'https://instance-a.example.com/storage/get/embedded/Report/r-1/';

      it.each([
        ['plain name', 'a.png', 'a.png'],
        ['space', 'sp%20ace.png', 'sp%20ace.png'],
        ['literal percent sequence', 'literal%2522quotes%2522.png', 'literal%2522quotes%2522.png'],
        ['percent sequence of a space', 'twin%20a%2520b.png', 'twin%20a%2520b.png'],
        ['lone percent', '100%25%20sure.png', '100%25%20sure.png'],
        ['hash, ampersand, plus', 'hash%20%231%20%26%20plus%2B.png', 'hash%20%231%20%26%20plus%2B.png'],
        ['unicode', '%C3%BCn%C3%AFc%C3%B6d%C3%A9.png', '%C3%BCn%C3%AFc%C3%B6d%C3%A9.png'],
      ])('keeps the stored file name of a relative url (%s)', (_label, markdownName, fetchName) => {
        expect(buildSyncStorageFetchUri(syncUri, `embedded/${markdownName}`, context)).toBe(`${fetchBase}${fetchName}`);
      });

      it('keeps the stored file name of an absolute url', () => {
        expect(buildSyncStorageFetchUri(syncUri, 'https://instance-b.example.com/embedded/twin%20a%2520b.png', context))
          .toBe(`${fetchBase}twin%20a%2520b.png`);
      });

      it('does not fail on a raw lone percent in the url', () => {
        expect(buildSyncStorageFetchUri(syncUri, 'embedded/100% sure.png', context)).toBe(`${fetchBase}100%25%20sure.png`);
      });

      it('drops the query string and the fragment of a relative url', () => {
        expect(buildSyncStorageFetchUri(syncUri, 'embedded/a.png?v=1', context)).toBe(`${fetchBase}a.png`);
        expect(buildSyncStorageFetchUri(syncUri, 'embedded/a.png#frag', context)).toBe(`${fetchBase}a.png`);
      });

      it('returns null for a relative url that is not an embedded file', () => {
        expect(buildSyncStorageFetchUri(syncUri, 'images/a.png', context)).toBeNull();
      });
    });

    it('returns null for a non-string storage uri', () => {
      expect(buildSyncStorageFetchUri(syncUri, null)).toBeNull();
      expect(buildSyncStorageFetchUri(syncUri, undefined)).toBeNull();
    });

    it('returns null when the storage uri does not point to a known storage path', () => {
      expect(buildSyncStorageFetchUri(syncUri, '/not/a/storage/path.csv')).toBeNull();
    });
  });
});
