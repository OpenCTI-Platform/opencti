import { describe, expect, it } from 'vitest';
import { validateSyncInflightStorageKey } from '../../../src/database/file-storage';

const SYNC_ID = 'sync-id-1';

describe('validateSyncInflightStorageKey', () => {
  it('accepts a well-formed inflight key scoped to the expected sync', () => {
    const result = validateSyncInflightStorageKey('sync/inflight/sync-id-1/remote-file-1/report.pdf', SYNC_ID);
    expect(result).toEqual({ valid: true, normalizedKey: 'sync/inflight/sync-id-1/remote-file-1/report.pdf' });
  });

  it('accepts and normalizes a percent-encoded but otherwise valid key', () => {
    const result = validateSyncInflightStorageKey('sync/inflight/sync-id-1/remote-file-1/report%20final.pdf', SYNC_ID);
    expect(result).toEqual({ valid: true, normalizedKey: 'sync/inflight/sync-id-1/remote-file-1/report final.pdf' });
  });

  it.each([undefined, null, 42, {}, [], ''])('rejects non-string or empty input: %s', (value) => {
    const result = validateSyncInflightStorageKey(value, SYNC_ID);
    expect(result.valid).toBe(false);
  });

  it('rejects a key outside the sync inflight root', () => {
    const result = validateSyncInflightStorageKey('import/Report/some-entity-id/report.pdf', SYNC_ID);
    expect(result.valid).toBe(false);
  });

  it('rejects a key that belongs to a different sync (ownership scoping)', () => {
    const result = validateSyncInflightStorageKey('sync/inflight/some-other-sync/remote-file-1/report.pdf', SYNC_ID);
    expect(result.valid).toBe(false);
  });

  it('rejects the bare prefix with no remoteFileId/filename beneath it', () => {
    const result = validateSyncInflightStorageKey('sync/inflight/sync-id-1/only-one-segment', SYNC_ID);
    expect(result.valid).toBe(false);
  });

  it('rejects path traversal via literal ".." segments', () => {
    const result = validateSyncInflightStorageKey('sync/inflight/sync-id-1/../../etc/passwd', SYNC_ID);
    expect(result.valid).toBe(false);
  });

  it('rejects path traversal hidden behind percent-encoding', () => {
    const result = validateSyncInflightStorageKey('sync/inflight/sync-id-1/%2e%2e/%2e%2e/etc/passwd', SYNC_ID);
    expect(result.valid).toBe(false);
  });

  it('rejects a hidden encoded slash smuggling extra segments past a naive prefix check', () => {
    const result = validateSyncInflightStorageKey('sync%2finflight%2fsync-id-1%2f..%2f..%2fetc%2fpasswd', SYNC_ID);
    expect(result.valid).toBe(false);
  });

  it('rejects absolute paths', () => {
    const result = validateSyncInflightStorageKey('/sync/inflight/sync-id-1/remote-file-1/report.pdf', SYNC_ID);
    expect(result.valid).toBe(false);
  });

  it('rejects protocol-like strings', () => {
    const result = validateSyncInflightStorageKey('s3://bucket/sync/inflight/sync-id-1/remote-file-1/report.pdf', SYNC_ID);
    expect(result.valid).toBe(false);
  });

  it('rejects backslashes', () => {
    const result = validateSyncInflightStorageKey('sync/inflight\\sync-id-1\\remote-file-1\\report.pdf', SYNC_ID);
    expect(result.valid).toBe(false);
  });

  it('rejects null bytes', () => {
    const result = validateSyncInflightStorageKey('sync/inflight/sync-id-1/remote-file-1/report.pdf\0.jpg', SYNC_ID);
    expect(result.valid).toBe(false);
  });

  it('rejects empty path segments (double slashes)', () => {
    const result = validateSyncInflightStorageKey('sync/inflight/sync-id-1//report.pdf', SYNC_ID);
    expect(result.valid).toBe(false);
  });

  it('rejects an invalid percent-encoding sequence', () => {
    const result = validateSyncInflightStorageKey('sync/inflight/sync-id-1/remote-file-1/report%.pdf', SYNC_ID);
    expect(result.valid).toBe(false);
  });

  it('rejects an oversized storage_key', () => {
    const result = validateSyncInflightStorageKey(`sync/inflight/sync-id-1/remote-file-1/${'a'.repeat(600)}.pdf`, SYNC_ID);
    expect(result.valid).toBe(false);
  });
});
