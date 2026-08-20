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
      const fetchUri = buildSyncStorageFetchUri(syncUri, fileUri);
      const parsed = new URL(fetchUri);
      expect(parsed.hash).toBe('');
      expect(parsed.search).toBe('');
      expect(parsed.pathname.endsWith('weird%23name%3Fx.csv')).toBe(true);
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
