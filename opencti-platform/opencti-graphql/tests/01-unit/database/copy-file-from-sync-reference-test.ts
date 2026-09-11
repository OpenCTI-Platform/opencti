import { afterEach, describe, expect, it, vi } from 'vitest';

const mockRawCopyFile = vi.fn();
const mockGetFileSize = vi.fn();
const mockDeleteFileFromStorage = vi.fn();
const mockIndexFileToDocument = vi.fn();
const mockFindById = vi.fn(async (..._args: unknown[]) => undefined as unknown);
const mockUnlock = vi.fn();
const mockLockResources = vi.fn(async (..._args: unknown[]) => ({ unlock: mockUnlock }));
const mockConnectorsForImport = vi.fn(async (..._args: unknown[]) => [] as unknown[]);

vi.mock('../../../src/database/raw-file-storage', () => ({
  rawCopyFile: (...args: unknown[]) => mockRawCopyFile(...args),
  getFileSize: (...args: unknown[]) => mockGetFileSize(...args),
  deleteFileFromStorage: (...args: unknown[]) => mockDeleteFileFromStorage(...args),
  rawListObjects: vi.fn(),
  rawUpload: vi.fn(),
}));
vi.mock('../../../src/modules/internal/document/document-domain', () => ({
  indexFileToDocument: (...args: unknown[]) => mockIndexFileToDocument(...args),
  allFilesForPaths: vi.fn(),
  deleteDocumentIndex: vi.fn(),
  findById: (...args: unknown[]) => mockFindById(...args),
}));
vi.mock('../../../src/lock/master-lock', () => ({
  lockResources: (...args: unknown[]) => mockLockResources(...args),
}));
// triggerJobImport's very first step is looking up eligible connectors; returning none here
// short-circuits the rest of uploadJobImport (createWork/pushToConnector/RabbitMQ) so this stays
// a unit test, while still letting us assert whether the import-trigger path ran at all.
vi.mock('../../../src/database/repository', () => ({
  connectorsForImport: (...args: unknown[]) => mockConnectorsForImport(...args),
}));
// Real confidence-level control needs the full schema-attributes registry (entity type
// registration) that isn't set up in this unit test; it's exercised in its own test suite.
vi.mock('../../../src/utils/confidence-level', () => ({
  controlUserConfidenceAgainstElement: () => true,
}));

const SYNC_ID = 'sync-id-1';
const context = {} as never;
const user = { id: 'user-1' } as never;

describe('copyFileFromSyncReference', () => {
  afterEach(() => {
    mockRawCopyFile.mockReset();
    mockGetFileSize.mockReset();
    mockDeleteFileFromStorage.mockReset();
    mockIndexFileToDocument.mockReset();
    mockFindById.mockReset();
    mockFindById.mockImplementation(async () => undefined);
    mockUnlock.mockReset();
    mockLockResources.mockReset();
    mockLockResources.mockImplementation(async () => ({ unlock: mockUnlock }));
    mockConnectorsForImport.mockReset();
    mockConnectorsForImport.mockImplementation(async () => []);
  });

  it('rejects a storage_key that does not belong to the calling sync, without touching S3', async () => {
    const { copyFileFromSyncReference } = await import('../../../src/database/file-storage');

    const result = await copyFileFromSyncReference(context, user, SYNC_ID, 'import/Report/entity-1', {
      storageKey: 'sync/inflight/some-other-sync/remote-file-1/content',
      name: 'report.pdf',
      entityId: 'entity-1',
    });

    expect(result).toBeNull();
    expect(mockLockResources).not.toHaveBeenCalled();
    expect(mockRawCopyFile).not.toHaveBeenCalled();
    expect(mockIndexFileToDocument).not.toHaveBeenCalled();
    expect(mockDeleteFileFromStorage).not.toHaveBeenCalled();
  });

  it('copies a validated storage_key to its final path, indexes it, and deletes the staged source', async () => {
    mockGetFileSize.mockResolvedValue(1234);
    const { copyFileFromSyncReference } = await import('../../../src/database/file-storage');

    const result = await copyFileFromSyncReference(context, user, SYNC_ID, 'import/Report/entity-1', {
      storageKey: 'sync/inflight/sync-id-1/remote-file-1/content',
      name: 'report.pdf',
      mimeType: 'application/pdf',
      version: '2024-01-01T00:00:00.000Z',
      fileMarkings: ['marking-1'],
      entityId: 'entity-1',
    });

    expect(mockRawCopyFile).toHaveBeenCalledWith('sync/inflight/sync-id-1/remote-file-1/content', 'import/Report/entity-1/report.pdf');
    expect(mockIndexFileToDocument).toHaveBeenCalledWith(context, expect.objectContaining({
      id: 'import/Report/entity-1/report.pdf',
      name: 'report.pdf',
      size: 1234,
      metaData: expect.objectContaining({
        version: '2024-01-01T00:00:00.000Z',
        mimetype: 'application/pdf',
        entity_id: 'entity-1',
        file_markings: ['marking-1'],
      }),
    }));
    expect(mockDeleteFileFromStorage).toHaveBeenCalledWith('sync/inflight/sync-id-1/remote-file-1/content');
    expect(result?.upload.id).toEqual('import/Report/entity-1/report.pdf');
    expect(result?.untouched).toEqual(false);
    expect(mockLockResources).toHaveBeenCalledWith(['sync-inflight-copy:sync/inflight/sync-id-1/remote-file-1/content'], { retryCount: 0 });
    expect(mockUnlock).toHaveBeenCalledTimes(1);
  });

  it('skips the copy and marks the result untouched when the target already has this version (re-sync of an already-attached file)', async () => {
    // Reproduces the real-world case that surfaced this bug: an entity whose file was already
    // fully copied/attached gets re-sent (e.g. an unrelated field changed, so the whole object --
    // including its file ref -- is re-processed by the destination). Without this guard,
    // stixCoreObjectImportPush would try to rebuild x_opencti_files identically to what's already
    // there, and jsonpatch would see no diff, throwing "...valid previous patch".
    mockFindById.mockResolvedValue({
      internal_id: 'import/Report/entity-1/report.pdf',
      metaData: { version: '2024-01-01T00:00:00.000Z', mimetype: 'application/pdf' },
    });
    const { copyFileFromSyncReference } = await import('../../../src/database/file-storage');

    const result = await copyFileFromSyncReference(context, user, SYNC_ID, 'import/Report/entity-1', {
      storageKey: 'sync/inflight/sync-id-1/remote-file-1/content',
      name: 'report.pdf',
      mimeType: 'application/pdf',
      version: '2024-01-01T00:00:00.000Z',
      entityId: 'entity-1',
    });

    expect(result?.untouched).toEqual(true);
    expect(mockRawCopyFile).not.toHaveBeenCalled();
    expect(mockIndexFileToDocument).not.toHaveBeenCalled();
    // The now-redundant staged source is still consumed, so it doesn't linger for the TTL backstop.
    expect(mockDeleteFileFromStorage).toHaveBeenCalledWith('sync/inflight/sync-id-1/remote-file-1/content');
  });

  it('still copies when the target exists but at an older version', async () => {
    mockGetFileSize.mockResolvedValue(1234);
    mockFindById.mockResolvedValue({
      internal_id: 'import/Report/entity-1/report.pdf',
      metaData: { version: '2023-01-01T00:00:00.000Z', mimetype: 'application/pdf' },
    });
    const { copyFileFromSyncReference } = await import('../../../src/database/file-storage');

    const result = await copyFileFromSyncReference(context, user, SYNC_ID, 'import/Report/entity-1', {
      storageKey: 'sync/inflight/sync-id-1/remote-file-1/content',
      name: 'report.pdf',
      mimeType: 'application/pdf',
      version: '2024-01-01T00:00:00.000Z',
      entityId: 'entity-1',
    });

    expect(result?.untouched).toEqual(false);
    expect(mockRawCopyFile).toHaveBeenCalled();
    expect(mockIndexFileToDocument).toHaveBeenCalled();
  });

  it('does not delete the staged source when the copy itself fails', async () => {
    mockRawCopyFile.mockRejectedValue(new Error('S3 unavailable'));
    const { copyFileFromSyncReference } = await import('../../../src/database/file-storage');

    const result = await copyFileFromSyncReference(context, user, SYNC_ID, 'import/Report/entity-1', {
      storageKey: 'sync/inflight/sync-id-1/remote-file-1/content',
      name: 'report.pdf',
      entityId: 'entity-1',
    });

    expect(result).toBeNull();
    expect(mockIndexFileToDocument).not.toHaveBeenCalled();
    expect(mockDeleteFileFromStorage).not.toHaveBeenCalled();
  });

  it('never lets a remote-controlled file name escape filePath via traversal or nested segments', async () => {
    mockGetFileSize.mockResolvedValue(10);
    const { copyFileFromSyncReference } = await import('../../../src/database/file-storage');

    const result = await copyFileFromSyncReference(context, user, SYNC_ID, 'import/Report/entity-1', {
      storageKey: 'sync/inflight/sync-id-1/remote-file-1/content',
      name: '../../../etc/passwd',
      entityId: 'entity-1',
    });

    const [, targetId] = mockRawCopyFile.mock.calls[0];
    expect(targetId).toEqual('import/Report/entity-1/passwd');
    expect(result?.upload.id).toEqual('import/Report/entity-1/passwd');
  });

  it('cannot be replayed: a storage_key already consumed once is gone from S3, so a second attempt fails', async () => {
    // Security model: since any caller with edit rights on some entity can call this (the
    // platform can't tell "the real sync worker" from any other caller by identity -- see
    // copyFileFromSyncReference's doc comment), the only thing that actually gates re-use is
    // that a consumed storage_key stops existing in S3. Simulate that: first call succeeds and
    // deletes the source (already covered above); a second call against the SAME key must find
    // nothing there and fail closed, exactly as if an attacker replayed an intercepted key.
    mockGetFileSize.mockResolvedValue(10);
    mockRawCopyFile.mockResolvedValueOnce(undefined);
    const { copyFileFromSyncReference } = await import('../../../src/database/file-storage');

    const firstAttempt = await copyFileFromSyncReference(context, user, SYNC_ID, 'import/Report/entity-1', {
      storageKey: 'sync/inflight/sync-id-1/remote-file-1/content',
      name: 'report.pdf',
      entityId: 'entity-1',
    });
    expect(firstAttempt).not.toBeNull();
    expect(mockDeleteFileFromStorage).toHaveBeenCalledWith('sync/inflight/sync-id-1/remote-file-1/content');

    // Second attempt: the object is gone now, so a real S3 backend would reject the copy.
    mockRawCopyFile.mockRejectedValueOnce(new Error('NoSuchKey: the specified key does not exist'));
    const replayAttempt = await copyFileFromSyncReference(context, user, SYNC_ID, 'import/Report/entity-attacker-controlled', {
      storageKey: 'sync/inflight/sync-id-1/remote-file-1/content',
      name: 'report.pdf',
      entityId: 'entity-attacker-controlled',
    });
    expect(replayAttempt).toBeNull();
  });

  it('rejects a second concurrent call racing on the same storage_key while the first is still in flight', async () => {
    // Simulates the TOCTOU window: two callers both pass validation for the same (leaked)
    // storage_key. Without an atomic claim, both could reach rawCopyFile before either deletes
    // the source. lockResources with retryCount: 0 means the loser fails fast instead of
    // queueing behind the winner.
    mockLockResources.mockImplementationOnce(async () => ({ unlock: mockUnlock }));
    mockLockResources.mockImplementationOnce(async () => {
      throw new Error('LockTimeoutError');
    });
    mockGetFileSize.mockResolvedValue(10);
    const { copyFileFromSyncReference } = await import('../../../src/database/file-storage');

    const copyProps = {
      storageKey: 'sync/inflight/sync-id-1/remote-file-1/content',
      name: 'report.pdf',
      entityId: 'entity-1',
    };
    const [first, second] = await Promise.all([
      copyFileFromSyncReference(context, user, SYNC_ID, 'import/Report/entity-1', copyProps),
      copyFileFromSyncReference(context, user, SYNC_ID, 'import/Report/entity-1', copyProps),
    ]);

    expect([first, second].filter((r) => r !== null)).toHaveLength(1);
    expect(mockRawCopyFile).toHaveBeenCalledTimes(1);
    expect(mockDeleteFileFromStorage).toHaveBeenCalledTimes(1);
  });

  it('still returns the file as successful when copy and index succeed but deleting the staged source fails', async () => {
    // A delete failure here is a cleanup problem, not a correctness problem: the file is already
    // durably copied and indexed, so the caller (and the entity it attaches to) must see success.
    // The leftover staging object is left for the syncInflightCleanupManager TTL backstop.
    mockGetFileSize.mockResolvedValue(10);
    mockDeleteFileFromStorage.mockRejectedValueOnce(new Error('S3 unavailable'));
    const { copyFileFromSyncReference } = await import('../../../src/database/file-storage');

    const result = await copyFileFromSyncReference(context, user, SYNC_ID, 'import/Report/entity-1', {
      storageKey: 'sync/inflight/sync-id-1/remote-file-1/content',
      name: 'report.pdf',
      entityId: 'entity-1',
    });

    expect(result).not.toBeNull();
    expect(result?.upload.id).toEqual('import/Report/entity-1/report.pdf');
    expect(mockIndexFileToDocument).toHaveBeenCalled();
    expect(mockDeleteFileFromStorage).toHaveBeenCalledWith('sync/inflight/sync-id-1/remote-file-1/content');
    // Lock must still be released even though the delete step failed.
    expect(mockUnlock).toHaveBeenCalledTimes(1);
  });

  it('triggers the import enrichment job for an import-eligible path, same as a direct upload', async () => {
    mockGetFileSize.mockResolvedValue(10);
    const { copyFileFromSyncReference } = await import('../../../src/database/file-storage');

    const result = await copyFileFromSyncReference(context, user, SYNC_ID, 'import/Report/entity-1', {
      storageKey: 'sync/inflight/sync-id-1/remote-file-1/content',
      name: 'report.pdf',
      entityId: 'entity-1',
      noTriggerImport: false,
      importContextEntities: [{ internal_id: 'entity-1', entity_type: 'Report' } as never],
    });

    expect(result).not.toBeNull();
    expect(mockConnectorsForImport).toHaveBeenCalled();
  });

  it('does not trigger the import enrichment job when no_trigger_import is set', async () => {
    mockGetFileSize.mockResolvedValue(10);
    const { copyFileFromSyncReference } = await import('../../../src/database/file-storage');

    const result = await copyFileFromSyncReference(context, user, SYNC_ID, 'import/Report/entity-1', {
      storageKey: 'sync/inflight/sync-id-1/remote-file-1/content',
      name: 'report.pdf',
      entityId: 'entity-1',
      noTriggerImport: true,
      importContextEntities: [{ internal_id: 'entity-1' } as never],
    });

    expect(result).not.toBeNull();
    expect(mockConnectorsForImport).not.toHaveBeenCalled();
  });

  it('does not trigger the import enrichment job outside an import-eligible path (e.g. embedded/)', async () => {
    mockGetFileSize.mockResolvedValue(10);
    const { copyFileFromSyncReference } = await import('../../../src/database/file-storage');

    const result = await copyFileFromSyncReference(context, user, SYNC_ID, 'embedded/Report/entity-1', {
      storageKey: 'sync/inflight/sync-id-1/remote-file-1/content',
      name: 'report.pdf',
      entityId: 'entity-1',
      noTriggerImport: false,
      importContextEntities: [{ internal_id: 'entity-1' } as never],
    });

    expect(result).not.toBeNull();
    expect(mockConnectorsForImport).not.toHaveBeenCalled();
  });

  it('still returns the file as successful when the import trigger step itself fails', async () => {
    // Same resilience contract as the delete-failure case above: the file is already copied and
    // indexed, so a failure in the best-effort enrichment trigger must not turn this into a
    // reported failure (the caller would otherwise retry against an already-consumed key).
    mockGetFileSize.mockResolvedValue(10);
    mockConnectorsForImport.mockRejectedValueOnce(new Error('ES unavailable'));
    const { copyFileFromSyncReference } = await import('../../../src/database/file-storage');

    const result = await copyFileFromSyncReference(context, user, SYNC_ID, 'import/Report/entity-1', {
      storageKey: 'sync/inflight/sync-id-1/remote-file-1/content',
      name: 'report.pdf',
      entityId: 'entity-1',
      noTriggerImport: false,
      importContextEntities: [], // global-import branch: calls connectorsForImport directly, no confidence check in the way
    });

    expect(result).not.toBeNull();
    expect(mockDeleteFileFromStorage).toHaveBeenCalled();
  });
});
